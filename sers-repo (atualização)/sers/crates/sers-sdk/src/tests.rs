use crate::*;
use sers_controlplane::{
    AuthorizationDecision, ClientBackendClaim, ControlPlane, ControlPlaneConfig, DenyReason,
    LocalDevKeyProvider, UnsupportedAttestationVerifier,
};
use sers_core::{
    ApplicationId, ExecutionPolicy, InstallationId, LicenseId, ModuleId, PublicKeyBytes,
    SersError, TenantId,
};
use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};
use sers_identity::InstallationIdentity;
use sers_package::PackageBuilder;
use sers_protocol::{Challenge, ChallengeRequest, ChallengeResponse, RegistrationRequest};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const NOW: u64 = 1_000_000;
const PLAINTEXT: &[u8] = b"protected business logic";

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Adapter that talks to an in-process Control Plane.
struct CpTransport {
    cp: Arc<ControlPlane>,
    clock: TestClock,
}

impl Transport for CpTransport {
    fn register_installation(
        &self,
        request: &RegistrationRequest,
        license: &LicenseId,
    ) -> Result<(), SersError> {
        self.cp
            .register_installation(request, license, self.clock.now())
    }

    fn request_challenge(&self, request: &ChallengeRequest) -> Result<Challenge, SersError> {
        self.cp.request_challenge(request, self.clock.now())
    }

    fn authorize(
        &self,
        response: &ChallengeResponse,
        claim: ClientClaim,
    ) -> Result<AuthorizationOutcome, SersError> {
        let claim = ClientBackendClaim {
            process_isolation: claim.process_isolation,
        };
        let decision = self
            .cp
            .authorize(response, &claim, None, self.clock.now())?;
        Ok(match decision {
            AuthorizationDecision::Granted(g) => {
                let g = *g;
                AuthorizationOutcome::Granted(Box::new(Grant {
                    authorization: g.authorization,
                    key_release: g.key_release,
                }))
            }
            AuthorizationDecision::RemoteOnly => AuthorizationOutcome::RemoteOnly,
            AuthorizationDecision::Denied(reason) => AuthorizationOutcome::Denied(match reason {
                DenyReason::InvalidChallenge => DenyKind::InvalidChallenge,
                DenyReason::NotAuthorized => DenyKind::NotAuthorized,
                DenyReason::HardwareAttestationRequired => DenyKind::HardwareAttestationRequired,
            }),
        })
    }
}

/// Returns a challenge that was altered in transit.
struct TamperingTransport(CpTransport);

impl Transport for TamperingTransport {
    fn register_installation(
        &self,
        request: &RegistrationRequest,
        license: &LicenseId,
    ) -> Result<(), SersError> {
        self.0.register_installation(request, license)
    }

    fn request_challenge(&self, request: &ChallengeRequest) -> Result<Challenge, SersError> {
        let mut challenge = self.0.request_challenge(request)?;
        challenge.package_digest = sers_core::Digest32::from_bytes([0xEE; 32]);
        Ok(challenge)
    }

    fn authorize(
        &self,
        response: &ChallengeResponse,
        claim: ClientClaim,
    ) -> Result<AuthorizationOutcome, SersError> {
        self.0.authorize(response, claim)
    }
}

struct World {
    cp: Arc<ControlPlane>,
    clock: TestClock,
    tenant: TenantId,
    app: ApplicationId,
    publisher: SigningKeyPair,
    package: Vec<u8>,
    license: LicenseId,
    authority_key: PublicKeyBytes,
}

fn world(policy: ExecutionPolicy) -> World {
    let clock = TestClock::new(NOW);
    let cp = Arc::new(
        ControlPlane::new(
            ControlPlaneConfig::default(),
            Box::new(LocalDevKeyProvider::generate().unwrap()),
            Box::new(SigningKeyPair::generate().unwrap()),
            Box::new(UnsupportedAttestationVerifier),
        )
        .unwrap(),
    );
    let tenant = TenantId::new("acme").unwrap();
    cp.create_tenant(tenant.clone(), NOW).unwrap();
    let app = ApplicationId::new("acme.editor").unwrap();
    let publisher = SigningKeyPair::generate().unwrap();
    cp.register_application(&tenant, app.clone(), policy, &[publisher.public_key()], NOW)
        .unwrap();
    let package_key = SymmetricKey::generate().unwrap();
    let mut builder = PackageBuilder::new(app.clone(), "1.0.0", 1, policy, NOW).unwrap();
    builder
        .add_module(ModuleId::new("core").unwrap(), 1, PLAINTEXT.to_vec())
        .unwrap();
    let package = builder.build(&publisher, &package_key).unwrap();
    cp.register_package(&tenant, &app, &package, &package_key, NOW)
        .unwrap();
    let license = cp.create_license(&tenant, &app, None, 5, NOW).unwrap();
    let authority_key = cp.authorization_public_key();
    World {
        cp,
        clock,
        tenant,
        app,
        publisher,
        package,
        license,
        authority_key,
    }
}

fn transport(w: &World) -> CpTransport {
    CpTransport {
        cp: Arc::clone(&w.cp),
        clock: w.clock.clone(),
    }
}

fn builder(w: &World) -> SersApplicationBuilder {
    SersApplicationBuilder::new()
        .application_id(w.app.clone())
        .license(w.license)
        .trust_publisher(w.publisher.public_key())
        .authority_key(w.authority_key)
        .identity(InstallationIdentity::generate().unwrap())
        .claim_process_isolation(true)
}

fn application(w: &World) -> SersApplication<CpTransport, TestClock> {
    builder(w)
        .build_with_clock(transport(w), w.clock.clone())
        .unwrap()
}

fn core_module() -> ModuleId {
    ModuleId::new("core").unwrap()
}

#[test]
fn full_flow_opens_the_package_and_decrypts_the_module() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    app.initialize().unwrap();
    let opened = app.open(w.package.clone()).unwrap();
    assert_eq!(opened.expires_at(), NOW + 300);
    assert_eq!(opened.module_ids().unwrap(), vec![core_module()]);
    let plain = app.module(&opened, &core_module()).unwrap();
    assert_eq!(&plain[..], PLAINTEXT);
    assert!(app
        .module(&opened, &ModuleId::new("missing").unwrap())
        .is_err());
    assert!(!format!("{opened:?}").contains("business"));
}

#[test]
fn initialize_is_idempotent() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    app.initialize().unwrap();
    app.initialize().unwrap();
}

#[test]
fn opening_without_registration_fails() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    assert!(app.open(w.package.clone()).is_err());
}

#[test]
fn revoked_installation_cannot_open() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    app.initialize().unwrap();
    let id: InstallationId = app.installation_id();
    w.cp.revoke_installation(&w.tenant, &id, NOW).unwrap();
    assert!(app.open(w.package.clone()).is_err());
}

#[test]
fn modules_stop_decrypting_when_the_authorization_expires() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    app.initialize().unwrap();
    let opened = app.open(w.package.clone()).unwrap();
    w.clock.set(NOW + 299);
    assert!(app.module(&opened, &core_module()).is_ok());
    w.clock.set(NOW + 300);
    assert_eq!(
        app.module(&opened, &core_module()).unwrap_err(),
        SersError::PolicyDenied("authorization expired")
    );
}

#[test]
fn clock_rollback_is_detected() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    app.initialize().unwrap();
    let opened = app.open(w.package.clone()).unwrap();
    w.clock.set(NOW - 100);
    assert_eq!(
        app.module(&opened, &core_module()).unwrap_err(),
        SersError::PolicyDenied("system clock moved backwards")
    );
}

#[test]
fn untrusted_publisher_is_rejected_locally() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = SersApplicationBuilder::new()
        .application_id(w.app.clone())
        .license(w.license)
        .trust_publisher(SigningKeyPair::generate().unwrap().public_key())
        .authority_key(w.authority_key)
        .identity(InstallationIdentity::generate().unwrap())
        .claim_process_isolation(true)
        .build_with_clock(transport(&w), w.clock.clone())
        .unwrap();
    app.initialize().unwrap();
    assert_eq!(
        app.open(w.package.clone()).unwrap_err(),
        SersError::PolicyDenied("untrusted publisher")
    );
}

#[test]
fn minimum_version_counter_blocks_old_packages() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = builder(&w)
        .min_version_counter(2)
        .build_with_clock(transport(&w), w.clock.clone())
        .unwrap();
    app.initialize().unwrap();
    assert!(app.open(w.package.clone()).is_err());
}

#[test]
fn tampered_package_is_rejected_before_any_network_use() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = application(&w);
    let mut bad = w.package.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(app.open(bad).is_err());
}

#[test]
fn hardware_required_is_denied_and_never_downgraded() {
    let w = world(ExecutionPolicy::HardwareRequired);
    let app = application(&w);
    app.initialize().unwrap();
    assert!(matches!(
        app.open(w.package.clone()),
        Err(SersError::PolicyDenied(_))
    ));
}

#[test]
fn remote_execution_policy_is_reported_as_unsupported() {
    let w = world(ExecutionPolicy::RemoteExecutionRequired);
    let app = application(&w);
    app.initialize().unwrap();
    assert!(matches!(
        app.open(w.package.clone()),
        Err(SersError::Unsupported(_))
    ));
}

#[test]
fn without_the_isolation_claim_software_policy_is_denied() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = builder(&w)
        .claim_process_isolation(false)
        .build_with_clock(transport(&w), w.clock.clone())
        .unwrap();
    app.initialize().unwrap();
    assert!(matches!(
        app.open(w.package.clone()),
        Err(SersError::PolicyDenied(_))
    ));
}

#[test]
fn authorization_from_the_wrong_authority_is_rejected() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = builder(&w)
        .authority_key(SigningKeyPair::generate().unwrap().public_key())
        .build_with_clock(transport(&w), w.clock.clone())
        .unwrap();
    app.initialize().unwrap();
    assert_eq!(
        app.open(w.package.clone()).unwrap_err(),
        SersError::SignatureInvalid
    );
}

#[test]
fn challenge_altered_in_transit_is_rejected() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let app = builder(&w)
        .build_with_clock(TamperingTransport(transport(&w)), w.clock.clone())
        .unwrap();
    app.initialize().unwrap();
    assert_eq!(
        app.open(w.package.clone()).unwrap_err(),
        SersError::Protocol("challenge does not match the request")
    );
}

#[test]
fn opened_package_cannot_be_used_by_another_installation() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let first = application(&w);
    first.initialize().unwrap();
    let opened = first.open(w.package.clone()).unwrap();
    let second = application(&w);
    assert!(second.module(&opened, &core_module()).is_err());
}

#[test]
fn builder_requires_every_mandatory_field() {
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let identity = || InstallationIdentity::generate().unwrap();
    let missing_app = SersApplicationBuilder::new()
        .license(w.license)
        .trust_publisher(w.publisher.public_key())
        .authority_key(w.authority_key)
        .identity(identity())
        .build(transport(&w));
    assert!(missing_app.is_err());
    let missing_publisher = SersApplicationBuilder::new()
        .application_id(w.app.clone())
        .license(w.license)
        .authority_key(w.authority_key)
        .identity(identity())
        .build(transport(&w));
    assert!(missing_publisher.is_err());
    let missing_identity = SersApplicationBuilder::new()
        .application_id(w.app.clone())
        .license(w.license)
        .trust_publisher(w.publisher.public_key())
        .authority_key(w.authority_key)
        .build(transport(&w));
    assert!(missing_identity.is_err());
}

#[cfg(unix)]
#[test]
fn identity_persists_through_a_key_store() {
    use sers_identity::FileKeyStore;
    let w = world(ExecutionPolicy::SoftwareAllowed);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("installation.key");
    let make = || {
        SersApplicationBuilder::new()
            .application_id(w.app.clone())
            .license(w.license)
            .trust_publisher(w.publisher.public_key())
            .authority_key(w.authority_key)
            .key_store(Box::new(FileKeyStore::new(path.clone())))
            .build_with_clock(transport(&w), w.clock.clone())
            .unwrap()
    };
    assert_eq!(make().installation_id(), make().installation_id());
}
