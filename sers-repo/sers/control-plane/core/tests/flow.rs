//! End-to-end security flows against the in-memory Control Plane, using the real
//! client identity, package builder and key release. Nothing here is mocked
//! except `TestOnlyVerifiedAttestation`, a test double used to exercise the
//! hardware *decision logic*; it is NOT a TEE and no such verifier ships.

use sers_controlplane::*;
use sers_core::{
    AttestationStatus, Digest32, ExecutionPlacement, ExecutionPolicy, LicenseId, ModuleId, Nonce32,
    SersError, TenantId, X25519PublicKey, ApplicationId,
};
use sers_crypto::{kex::EphemeralKeyPair, secret::SymmetricKey, sign::SigningKeyPair};
use sers_identity::InstallationIdentity;
use sers_package::{PackageBuilder, RawPackage};
use sers_protocol::{
    open_key_release, Challenge, ChallengeRequest, ChallengeResponse, KeyReleaseContext,
    PROTOCOL_VERSION,
};

const NOW: u64 = 1_000_000;
const SOFT: ClientBackendClaim = ClientBackendClaim {
    process_isolation: true,
};
const PLAINTEXT: &[u8] = b"secret business logic";

struct TestOnlyVerifiedAttestation;

impl AttestationVerifier for TestOnlyVerifiedAttestation {
    fn verify(&self, _e: Option<&AttestationEvidence>, _n: &Nonce32) -> AttestationOutcome {
        AttestationOutcome {
            status: AttestationStatus::Verified,
            hardware_backed: true,
        }
    }
}

struct World {
    cp: ControlPlane,
    tenant: TenantId,
    app: ApplicationId,
    publisher: SigningKeyPair,
    package_key: SymmetricKey,
    package_bytes: Vec<u8>,
    package_digest: Digest32,
    license: LicenseId,
}

fn app_id(s: &str) -> ApplicationId {
    ApplicationId::new(s).unwrap()
}

fn build_package(
    app: &ApplicationId,
    policy: ExecutionPolicy,
    counter: u64,
    publisher: &SigningKeyPair,
    key: &SymmetricKey,
) -> Vec<u8> {
    let mut b = PackageBuilder::new(app.clone(), "1.0.0", counter, policy, NOW).unwrap();
    b.add_module(ModuleId::new("core").unwrap(), 1, PLAINTEXT.to_vec())
        .unwrap();
    b.build(publisher, key).unwrap()
}

fn digest_of(bytes: &[u8]) -> Digest32 {
    RawPackage::parse(bytes).unwrap().manifest_digest()
}

fn new_cp(att: Box<dyn AttestationVerifier>) -> ControlPlane {
    ControlPlane::new(
        ControlPlaneConfig::default(),
        Box::new(LocalDevKeyProvider::generate().unwrap()),
        Box::new(SigningKeyPair::generate().unwrap()),
        att,
    )
    .unwrap()
}

fn world_with(
    policy: ExecutionPolicy,
    att: Box<dyn AttestationVerifier>,
    max_installations: u32,
) -> World {
    let cp = new_cp(att);
    let tenant = TenantId::new("acme").unwrap();
    let api_key = cp.create_tenant(tenant.clone(), NOW).unwrap();
    assert_eq!(cp.authenticate(&api_key).unwrap(), tenant);
    let app = app_id("acme.editor");
    let publisher = SigningKeyPair::generate().unwrap();
    cp.register_application(&tenant, app.clone(), policy, &[publisher.public_key()], NOW)
        .unwrap();
    let package_key = SymmetricKey::generate().unwrap();
    let package_bytes = build_package(&app, policy, 1, &publisher, &package_key);
    cp.register_package(&tenant, &app, &package_bytes, &package_key, NOW)
        .unwrap();
    let license = cp
        .create_license(&tenant, &app, None, max_installations, NOW)
        .unwrap();
    World {
        package_digest: digest_of(&package_bytes),
        cp,
        tenant,
        app,
        publisher,
        package_key,
        package_bytes,
        license,
    }
}

fn world(policy: ExecutionPolicy) -> World {
    world_with(policy, Box::new(UnsupportedAttestationVerifier), 2)
}

fn register_client(w: &World) -> InstallationIdentity {
    let identity = InstallationIdentity::generate().unwrap();
    w.cp
        .register_installation(&identity.registration_request(&w.app), &w.license, NOW)
        .unwrap();
    identity
}

struct Attempt {
    decision: AuthorizationDecision,
    challenge: Challenge,
    response: ChallengeResponse,
    eph: EphemeralKeyPair,
}

fn authorize_once(w: &World, identity: &InstallationIdentity, now: u64) -> Attempt {
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let challenge = w.cp.request_challenge(&req, now).unwrap();
    let response = identity.respond_to(&challenge).unwrap();
    let decision = w.cp.authorize(&response, &SOFT, None, now + 1).unwrap();
    Attempt {
        decision,
        challenge,
        response,
        eph,
    }
}

fn expect_grant(d: AuthorizationDecision) -> Grant {
    match d {
        AuthorizationDecision::Granted(g) => g,
        other => panic!("expected a grant, got {other:?}"),
    }
}

fn assert_denied(d: &AuthorizationDecision, reason: DenyReason) {
    assert_eq!(d, &AuthorizationDecision::Denied(reason));
}

#[test]
fn full_flow_grants_and_the_client_can_decrypt_the_module() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let a = authorize_once(&w, &identity, NOW);
    let grant = expect_grant(a.decision);

    let installation_id = identity.id();
    grant
        .authorization
        .verify(
            &w.cp.authorization_public_key(),
            &w.app,
            &installation_id,
            &w.package_digest,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(
        grant.authorization.token.placement,
        ExecutionPlacement::LocalSoftware
    );

    let ctx = KeyReleaseContext {
        nonce: &a.challenge.nonce,
        application_id: &w.app,
        installation_id: &installation_id,
        package_digest: &w.package_digest,
    };
    let key = open_key_release(&ctx, a.eph, &grant.key_release).unwrap();
    assert_eq!(key.expose(), w.package_key.expose());

    let verified = RawPackage::parse(&w.package_bytes)
        .unwrap()
        .verify(&w.publisher.public_key())
        .unwrap();
    let plain = verified
        .decrypt_module(&key, &ModuleId::new("core").unwrap())
        .unwrap();
    assert_eq!(&plain[..], PLAINTEXT);
}

#[test]
fn replayed_response_is_denied() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let a = authorize_once(&w, &identity, NOW);
    expect_grant(a.decision);
    let again = w.cp.authorize(&a.response, &SOFT, None, NOW + 3).unwrap();
    assert_denied(&again, DenyReason::InvalidChallenge);
}

#[test]
fn expired_challenge_is_denied() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let challenge = w.cp.request_challenge(&req, NOW).unwrap();
    let response = identity.respond_to(&challenge).unwrap();
    let d = w.cp.authorize(&response, &SOFT, None, NOW + 1_000).unwrap();
    assert_denied(&d, DenyReason::InvalidChallenge);
}

#[test]
fn response_signed_by_another_key_is_denied() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let victim = register_client(&w);
    let attacker = InstallationIdentity::generate().unwrap();
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: victim.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let challenge = w.cp.request_challenge(&req, NOW).unwrap();
    let forged = ChallengeResponse {
        version: PROTOCOL_VERSION,
        nonce: challenge.nonce,
        signature: SigningKeyPair::generate().unwrap().sign(&challenge.signing_bytes()),
    };
    let d = w.cp.authorize(&forged, &SOFT, None, NOW + 1).unwrap();
    assert_denied(&d, DenyReason::InvalidChallenge);
    // the attacker's own identity cannot even obtain a challenge for it
    assert!(attacker.respond_to(&challenge).is_err());
}

#[test]
fn hardware_required_fails_closed_without_verified_attestation() {
    let w = world(ExecutionPolicy::HardwareRequired);
    let identity = register_client(&w);
    let a = authorize_once(&w, &identity, NOW);
    assert_denied(&a.decision, DenyReason::HardwareAttestationRequired);
}

#[test]
fn hardware_decision_logic_grants_local_hardware_when_attestation_is_verified() {
    // Test double only: proves the policy wiring, not any TEE.
    let w = world_with(
        ExecutionPolicy::HardwareRequired,
        Box::new(TestOnlyVerifiedAttestation),
        2,
    );
    let identity = register_client(&w);
    let a = authorize_once(&w, &identity, NOW);
    let grant = expect_grant(a.decision);
    assert_eq!(
        grant.authorization.token.placement,
        ExecutionPlacement::LocalHardware
    );
}

#[test]
fn remote_execution_required_releases_no_key() {
    let w = world(ExecutionPolicy::RemoteExecutionRequired);
    let identity = register_client(&w);
    let a = authorize_once(&w, &identity, NOW);
    assert_eq!(a.decision, AuthorizationDecision::RemoteOnly);
}

#[test]
fn client_claim_without_process_isolation_gets_no_software_grant() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let ch = w.cp.request_challenge(&req, NOW).unwrap();
    let resp = identity.respond_to(&ch).unwrap();
    let none = ClientBackendClaim::default();
    let d = w.cp.authorize(&resp, &none, None, NOW + 1).unwrap();
    assert_denied(&d, DenyReason::NotAuthorized);
}

#[test]
fn revoked_installation_gets_no_challenge_and_no_key() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);

    // challenge issued before revocation
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let pending = w.cp.request_challenge(&req, NOW).unwrap();
    let pending_resp = identity.respond_to(&pending).unwrap();

    w.cp.revoke_installation(&w.tenant, &identity.id(), NOW + 1).unwrap();

    assert!(w.cp.request_challenge(&req, NOW + 2).is_err());
    let d = w.cp.authorize(&pending_resp, &SOFT, None, NOW + 2).unwrap();
    assert_denied(&d, DenyReason::NotAuthorized);

    // a revoked installation cannot re-register
    let again = w.cp.register_installation(&identity.registration_request(&w.app), &w.license, NOW + 3);
    assert!(again.is_err());
}

#[test]
fn license_suspension_revocation_and_expiry_block_authorization() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);

    w.cp.set_license_status(&w.tenant, &w.license, LicenseStatus::Suspended, NOW).unwrap();
    assert_denied(&authorize_once(&w, &identity, NOW + 1).decision, DenyReason::NotAuthorized);

    w.cp.set_license_status(&w.tenant, &w.license, LicenseStatus::Active, NOW + 2).unwrap();
    expect_grant(authorize_once(&w, &identity, NOW + 3).decision);

    w.cp.set_license_status(&w.tenant, &w.license, LicenseStatus::Revoked, NOW + 4).unwrap();
    assert_denied(&authorize_once(&w, &identity, NOW + 5).decision, DenyReason::NotAuthorized);

    // expiring license
    let expiring = w.cp.create_license(&w.tenant, &w.app, Some(NOW + 100), 1, NOW).unwrap();
    let other = InstallationIdentity::generate().unwrap();
    w.cp.register_installation(&other.registration_request(&w.app), &expiring, NOW).unwrap();
    expect_grant(authorize_once(&w, &other, NOW + 10).decision);
    assert_denied(&authorize_once(&w, &other, NOW + 200).decision, DenyReason::NotAuthorized);
}

#[test]
fn expired_license_cannot_register_new_installations() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let l = w.cp.create_license(&w.tenant, &w.app, Some(NOW + 10), 5, NOW).unwrap();
    let id = InstallationIdentity::generate().unwrap();
    let r = w.cp.register_installation(&id.registration_request(&w.app), &l, NOW + 10);
    assert!(r.is_err());
}

#[test]
fn revoked_package_and_disabled_application_block_authorization() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let package_id = RawPackage::parse(&w.package_bytes)
        .unwrap()
        .verify(&w.publisher.public_key())
        .unwrap()
        .manifest()
        .package_id;

    w.cp.set_application_enabled(&w.tenant, &w.app, false, NOW).unwrap();
    assert_denied(&authorize_once(&w, &identity, NOW + 1).decision, DenyReason::NotAuthorized);
    w.cp.set_application_enabled(&w.tenant, &w.app, true, NOW + 2).unwrap();
    expect_grant(authorize_once(&w, &identity, NOW + 3).decision);

    w.cp.revoke_package(&w.tenant, &w.app, &package_id, NOW + 4).unwrap();
    assert_denied(&authorize_once(&w, &identity, NOW + 5).decision, DenyReason::NotAuthorized);
}

#[test]
fn downgrade_is_blocked_at_registration_and_at_authorization() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);

    // registered package has counter 1; raise the floor to 2
    w.cp.set_min_version_counter(&w.tenant, &w.app, 2, NOW).unwrap();
    assert_denied(&authorize_once(&w, &identity, NOW + 1).decision, DenyReason::NotAuthorized);

    let old_key = SymmetricKey::generate().unwrap();
    let old = build_package(&w.app, ExecutionPolicy::SoftwareAllowed, 1, &w.publisher, &old_key);
    assert!(w.cp.register_package(&w.tenant, &w.app, &old, &old_key, NOW + 2).is_err());

    let new_key = SymmetricKey::generate().unwrap();
    let newer = build_package(&w.app, ExecutionPolicy::SoftwareAllowed, 2, &w.publisher, &new_key);
    w.cp.register_package(&w.tenant, &w.app, &newer, &new_key, NOW + 3).unwrap();

    // lowering the floor is impossible
    w.cp.set_min_version_counter(&w.tenant, &w.app, 0, NOW + 4).unwrap();
    assert!(w.cp.register_package(&w.tenant, &w.app, &old, &old_key, NOW + 5).is_err());
}

#[test]
fn unregistered_package_digest_is_denied() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let key = SymmetricKey::generate().unwrap();
    let rogue = build_package(&w.app, ExecutionPolicy::SoftwareAllowed, 9, &w.publisher, &key);
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: digest_of(&rogue),
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    let ch = w.cp.request_challenge(&req, NOW).unwrap();
    let resp = identity.respond_to(&ch).unwrap();
    let d = w.cp.authorize(&resp, &SOFT, None, NOW + 1).unwrap();
    assert_denied(&d, DenyReason::NotAuthorized);
}

#[test]
fn tenants_are_isolated() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    let other = TenantId::new("globex").unwrap();
    w.cp.create_tenant(other.clone(), NOW).unwrap();

    // cannot claim the application id
    assert!(w.cp
        .register_application(&other, w.app.clone(), ExecutionPolicy::SoftwareAllowed, &[w.publisher.public_key()], NOW)
        .is_err());
    // cannot touch another tenant's resources
    assert!(w.cp.create_license(&other, &w.app, None, 1, NOW).is_err());
    assert!(w.cp.revoke_installation(&other, &identity.id(), NOW).is_err());
    assert!(w.cp.set_license_status(&other, &w.license, LicenseStatus::Revoked, NOW).is_err());
    assert!(w.cp.set_min_version_counter(&other, &w.app, 99, NOW).is_err());
    assert!(w.cp.set_application_enabled(&other, &w.app, false, NOW).is_err());
    assert!(w.cp.register_package(&other, &w.app, &w.package_bytes, &w.package_key, NOW).is_err());
    let package_id = RawPackage::parse(&w.package_bytes).unwrap()
        .verify(&w.publisher.public_key()).unwrap().manifest().package_id;
    assert!(w.cp.revoke_package(&other, &w.app, &package_id, NOW).is_err());

    // the legitimate tenant is unaffected
    expect_grant(authorize_once(&w, &identity, NOW + 1).decision);
}

#[test]
fn installation_requires_proof_of_possession_and_a_matching_license() {
    let w = world(ExecutionPolicy::SoftwareAllowed);

    // swapped public key: id no longer derives from it
    let a = InstallationIdentity::generate().unwrap();
    let b = InstallationIdentity::generate().unwrap();
    let mut req = a.registration_request(&w.app);
    req.public_key = b.public_key();
    assert!(w.cp.register_installation(&req, &w.license, NOW).is_err());

    // proof made for another application
    let mut req = a.registration_request(&app_id("acme.other"));
    req.application_id = w.app.clone();
    assert!(w.cp.register_installation(&req, &w.license, NOW).is_err());

    // license of another application
    let other_app = app_id("acme.second");
    let pubkey = SigningKeyPair::generate().unwrap().public_key();
    w.cp.register_application(&w.tenant, other_app.clone(), ExecutionPolicy::SoftwareAllowed, &[pubkey], NOW).unwrap();
    let foreign = w.cp.create_license(&w.tenant, &other_app, None, 1, NOW).unwrap();
    assert!(w.cp.register_installation(&a.registration_request(&w.app), &foreign, NOW).is_err());

    // unknown license
    let unknown = LicenseId::from_bytes([7; 16]);
    assert!(w.cp.register_installation(&a.registration_request(&w.app), &unknown, NOW).is_err());
}

#[test]
fn license_installation_limit_is_enforced_and_registration_is_idempotent() {
    let w = world_with(ExecutionPolicy::SoftwareAllowed, Box::new(UnsupportedAttestationVerifier), 1);
    let first = register_client(&w);
    let second = InstallationIdentity::generate().unwrap();
    assert!(w.cp.register_installation(&second.registration_request(&w.app), &w.license, NOW).is_err());
    assert!(w.cp.register_installation(&first.registration_request(&w.app), &w.license, NOW + 1).is_ok());
}

#[test]
fn strangers_cannot_get_challenges() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let stranger = InstallationIdentity::generate().unwrap();
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: stranger.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    assert!(w.cp.request_challenge(&req, NOW).is_err());
}

#[test]
fn package_registration_rejects_untrusted_tampered_and_mismatched_packages() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let key = SymmetricKey::generate().unwrap();

    let stranger = SigningKeyPair::generate().unwrap();
    let from_stranger = build_package(&w.app, ExecutionPolicy::SoftwareAllowed, 5, &stranger, &key);
    assert!(w.cp.register_package(&w.tenant, &w.app, &from_stranger, &key, NOW).is_err());

    let good = build_package(&w.app, ExecutionPolicy::SoftwareAllowed, 5, &w.publisher, &key);
    let wrong_key = SymmetricKey::generate().unwrap();
    assert!(w.cp.register_package(&w.tenant, &w.app, &good, &wrong_key, NOW).is_err());

    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(w.cp.register_package(&w.tenant, &w.app, &tampered, &key, NOW).is_err());

    let wrong_policy = build_package(&w.app, ExecutionPolicy::HardwareRequired, 6, &w.publisher, &key);
    assert!(w.cp.register_package(&w.tenant, &w.app, &wrong_policy, &key, NOW).is_err());

    let other_app = build_package(&app_id("acme.other"), ExecutionPolicy::SoftwareAllowed, 7, &w.publisher, &key);
    assert!(w.cp.register_package(&w.tenant, &w.app, &other_app, &key, NOW).is_err());

    // the good one still registers, but only once
    assert!(w.cp.register_package(&w.tenant, &w.app, &good, &key, NOW).is_ok());
    assert!(w.cp.register_package(&w.tenant, &w.app, &good, &key, NOW).is_err());
}

#[test]
fn api_keys_authenticate_only_their_tenant() {
    let cp = new_cp(Box::new(UnsupportedAttestationVerifier));
    let a = TenantId::new("alpha").unwrap();
    let b = TenantId::new("bravo").unwrap();
    let key_a = cp.create_tenant(a.clone(), NOW).unwrap();
    let key_b = cp.create_tenant(b.clone(), NOW).unwrap();
    assert_ne!(key_a, key_b);
    assert_eq!(cp.authenticate(&key_a).unwrap(), a);
    assert_eq!(cp.authenticate(&key_b).unwrap(), b);
    assert!(cp.authenticate("not-a-key").is_err());
    assert!(cp.authenticate("").is_err());
    assert!(cp.create_tenant(a, NOW).is_err());
}

#[test]
fn audit_log_is_consistent_and_never_contains_secrets() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = register_client(&w);
    expect_grant(authorize_once(&w, &identity, NOW).decision);
    w.cp.revoke_installation(&w.tenant, &identity.id(), NOW + 5).unwrap();
    let a = authorize_once_expect_error(&w, &identity);
    assert!(a);

    assert!(w.cp.verify_audit_chain());
    let events = w.cp.audit_events();
    assert!(events.iter().any(|e| e.action == "key.release" && e.allowed));
    assert!(events.iter().any(|e| e.action == "installation.revoke"));
    let license_hex = w.license.to_string();
    for e in &events {
        assert!(!e.subject.contains(&license_hex));
        assert!(!e.detail.contains(&license_hex));
    }
}

fn authorize_once_expect_error(w: &World, identity: &InstallationIdentity) -> bool {
    let eph = EphemeralKeyPair::generate();
    let req = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: w.app.clone(),
        installation_id: identity.id(),
        package_digest: w.package_digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(eph.public_key()),
    };
    matches!(
        w.cp.request_challenge(&req, NOW + 6),
        Err(SersError::PolicyDenied(_))
    )
}
