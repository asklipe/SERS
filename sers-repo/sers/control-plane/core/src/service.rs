use crate::attestation::{AttestationEvidence, AttestationVerifier};
use crate::audit::AuditEvent;
use crate::keys::{KeyProvider, TokenSigner};
use crate::state::{
    AppStatus, Application, Installation, InstallationStatus, License, LicenseStatus,
    PackageRecord, PackageStatus, State,
};
use sers_core::{
    decide_placement, ApplicationId, BackendCapabilities, ExecutionPlacement, ExecutionPolicy,
    InstallationId, LicenseId, Nonce32, PackageId, PublicKeyBytes, SersError, TenantId,
};
use sers_crypto::{hash::sha256_parts, random::random_array, secret::SymmetricKey};
use sers_package::{publisher_key_id_from_public_key, RawPackage};
use sers_protocol::{
    seal_key_release, AuthorizationToken, Challenge, ChallengeAuthority, ChallengeRequest,
    ChallengeResponse, InMemoryChallengeStore, KeyRelease, KeyReleaseContext, RegistrationRequest,
    SignedAuthorization, MAX_AUTHORIZATION_TTL_SECS, PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, Copy)]
pub struct ControlPlaneConfig {
    pub challenge_ttl_secs: u64,
    pub authorization_ttl_secs: u64,
    pub max_outstanding_challenges: usize,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            challenge_ttl_secs: 60,
            authorization_ttl_secs: 300,
            max_outstanding_challenges: 10_000,
        }
    }
}

/// What the client says about its own backend. Only `process_isolation` is
/// read, and it is an unverifiable claim: it can enable `software_allowed`
/// placement but never a hardware placement.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientBackendClaim {
    pub process_isolation: bool,
}

/// Coarse reasons returned to clients. Detailed reasons go to the audit log
/// only, so policy internals are not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    InvalidChallenge,
    NotAuthorized,
    HardwareAttestationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub authorization: SignedAuthorization,
    pub key_release: KeyRelease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// Execute locally; the package key is sealed to the requesting session.
    Granted(Grant),
    /// Policy requires remote execution: no key is released to the client.
    RemoteOnly,
    Denied(DenyReason),
}

pub struct ControlPlane {
    config: ControlPlaneConfig,
    state: Mutex<State>,
    challenges: ChallengeAuthority<InMemoryChallengeStore>,
    keys: Box<dyn KeyProvider>,
    signer: Box<dyn TokenSigner>,
    attestation: Box<dyn AttestationVerifier>,
}

fn hash_api_key(key: &str) -> [u8; 32] {
    sha256_parts(&[&b"SERS-API-KEY-v1\0"[..], key.as_bytes()])
}

fn package_key_context(application: &ApplicationId, package: &PackageId) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(b"SERS-PACKAGE-KEY-v1\0");
    b.extend_from_slice(package.as_bytes());
    b.extend_from_slice(application.as_str().as_bytes());
    b
}

fn license_usable(l: &License, now: u64) -> bool {
    let not_expired = match l.expires_at {
        Some(expiry) => now < expiry,
        None => true,
    };
    l.status == LicenseStatus::Active && not_expired
}

fn not_found() -> SersError {
    SersError::PolicyDenied("not found")
}

fn owned_app<'a>(
    s: &'a State,
    tenant: &TenantId,
    app: &ApplicationId,
) -> Result<&'a Application, SersError> {
    match s.apps.get(app) {
        Some(a) if &a.tenant == tenant => Ok(a),
        _ => Err(not_found()),
    }
}

fn owned_app_mut<'a>(
    s: &'a mut State,
    tenant: &TenantId,
    app: &ApplicationId,
) -> Result<&'a mut Application, SersError> {
    match s.apps.get_mut(app) {
        Some(a) if &a.tenant == tenant => Ok(a),
        _ => Err(not_found()),
    }
}

impl ControlPlane {
    pub fn new(
        config: ControlPlaneConfig,
        keys: Box<dyn KeyProvider>,
        signer: Box<dyn TokenSigner>,
        attestation: Box<dyn AttestationVerifier>,
    ) -> Result<Self, SersError> {
        if config.authorization_ttl_secs == 0
            || config.authorization_ttl_secs > MAX_AUTHORIZATION_TTL_SECS
        {
            return Err(SersError::InvalidInput("authorization ttl out of range"));
        }
        let challenges = ChallengeAuthority::new(
            InMemoryChallengeStore::new(config.max_outstanding_challenges),
            config.challenge_ttl_secs,
        )?;
        Ok(Self {
            config,
            state: Mutex::new(State::default()),
            challenges,
            keys,
            signer,
            attestation,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Public key clients use to verify authorization tokens.
    pub fn authorization_public_key(&self) -> PublicKeyBytes {
        self.signer.public_key()
    }

    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.lock().audit.events().to_vec()
    }

    pub fn verify_audit_chain(&self) -> bool {
        self.lock().audit.verify_chain()
    }

    // ------------------------------------------------------------------
    // Platform / management API (tenant-scoped)
    // ------------------------------------------------------------------

    /// Creates a tenant and returns its API key. The key is shown once; only a
    /// hash is stored.
    pub fn create_tenant(&self, id: TenantId, now: u64) -> Result<String, SersError> {
        let api_key = Nonce32::from_bytes(random_array::<32>()?).to_string();
        let mut s = self.lock();
        if s.tenants.contains(&id) {
            return Err(SersError::PolicyDenied("tenant already exists"));
        }
        s.tenants.insert(id.clone());
        s.api_keys.insert(hash_api_key(&api_key), id.clone());
        s.audit
            .append(now, Some(&id), "tenant.create", id.to_string(), true, "ok");
        Ok(api_key)
    }

    pub fn authenticate(&self, api_key: &str) -> Result<TenantId, SersError> {
        self.lock()
            .api_keys
            .get(&hash_api_key(api_key))
            .cloned()
            .ok_or(SersError::PolicyDenied("invalid credentials"))
    }

    pub fn register_application(
        &self,
        tenant: &TenantId,
        application_id: ApplicationId,
        policy: ExecutionPolicy,
        publisher_keys: &[PublicKeyBytes],
        now: u64,
    ) -> Result<(), SersError> {
        if publisher_keys.is_empty() || publisher_keys.len() > 16 {
            return Err(SersError::InvalidInput("1 to 16 publisher keys required"));
        }
        let mut s = self.lock();
        if !s.tenants.contains(tenant) {
            return Err(SersError::PolicyDenied("unknown tenant"));
        }
        if s.apps.contains_key(&application_id) {
            return Err(SersError::PolicyDenied("application id unavailable"));
        }
        let keys: HashMap<_, _> = publisher_keys
            .iter()
            .map(|k| (publisher_key_id_from_public_key(k), *k))
            .collect();
        s.apps.insert(
            application_id.clone(),
            Application {
                tenant: tenant.clone(),
                execution_policy: policy,
                publisher_keys: keys,
                min_version_counter: 0,
                status: AppStatus::Active,
            },
        );
        s.audit.append(
            now,
            Some(tenant),
            "application.register",
            application_id.to_string(),
            true,
            "ok",
        );
        Ok(())
    }

    /// Enables or disables an application: disabled applications get no new
    /// authorizations or key releases.
    pub fn set_application_enabled(
        &self,
        tenant: &TenantId,
        application_id: &ApplicationId,
        enabled: bool,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        owned_app_mut(&mut s, tenant, application_id)?.status = if enabled {
            AppStatus::Active
        } else {
            AppStatus::Disabled
        };
        s.audit.append(
            now,
            Some(tenant),
            "application.set_enabled",
            application_id.to_string(),
            true,
            if enabled { "enabled" } else { "disabled" },
        );
        Ok(())
    }

    /// Raises the minimum accepted package version (anti-downgrade). The floor
    /// can only go up.
    pub fn set_min_version_counter(
        &self,
        tenant: &TenantId,
        application_id: &ApplicationId,
        counter: u64,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        {
            let app = owned_app_mut(&mut s, tenant, application_id)?;
            app.min_version_counter = app.min_version_counter.max(counter);
        }
        s.audit.append(
            now,
            Some(tenant),
            "application.min_version",
            application_id.to_string(),
            true,
            "ok",
        );
        Ok(())
    }

    /// Registers a signed package together with its package key. The package is
    /// fully verified (publisher key, signature, manifest, module hashes) and
    /// the key is proven to unwrap every module key before anything is stored.
    pub fn register_package(
        &self,
        tenant: &TenantId,
        application_id: &ApplicationId,
        package_bytes: &[u8],
        package_key: &SymmetricKey,
        now: u64,
    ) -> Result<PackageId, SersError> {
        let mut s = self.lock();
        let result =
            self.register_package_inner(&mut s, tenant, application_id, package_bytes, package_key);
        match &result {
            Ok(id) => s.audit.append(
                now,
                Some(tenant),
                "package.register",
                id.to_string(),
                true,
                "ok",
            ),
            Err(_) => s.audit.append(
                now,
                Some(tenant),
                "package.register",
                application_id.to_string(),
                false,
                "rejected",
            ),
        }
        result
    }

    fn register_package_inner(
        &self,
        s: &mut State,
        tenant: &TenantId,
        application_id: &ApplicationId,
        package_bytes: &[u8],
        package_key: &SymmetricKey,
    ) -> Result<PackageId, SersError> {
        let raw = RawPackage::parse(package_bytes)?;
        let app = owned_app(s, tenant, application_id)?;
        let publisher_key = *app
            .publisher_keys
            .get(&raw.publisher_key_id())
            .ok_or(SersError::PolicyDenied("untrusted publisher"))?;
        let policy = app.execution_policy;
        let min_counter = app.min_version_counter;

        let verified = raw.verify(&publisher_key)?;
        let manifest = verified.manifest();
        if &manifest.application_id != application_id {
            return Err(SersError::Protocol("package belongs to another application"));
        }
        if manifest.execution_policy != policy {
            return Err(SersError::PolicyDenied(
                "package policy differs from application policy",
            ));
        }
        if manifest.version_counter < min_counter {
            return Err(SersError::PolicyDenied(
                "package version below minimum accepted",
            ));
        }
        verified.verify_integrity()?;
        verified.check_package_key(package_key)?;

        let digest = verified.manifest_digest();
        let package_id = manifest.package_id;
        let version_counter = manifest.version_counter;
        if s.packages.contains_key(&(application_id.clone(), digest))
            || s.packages.values().any(|p| p.package_id == package_id)
        {
            return Err(SersError::PolicyDenied("package already registered"));
        }
        let wrapped_key = self
            .keys
            .wrap(&package_key_context(application_id, &package_id), package_key)?;
        s.packages.insert(
            (application_id.clone(), digest),
            PackageRecord {
                tenant: tenant.clone(),
                package_id,
                version_counter,
                status: PackageStatus::Active,
                wrapped_key,
            },
        );
        Ok(package_id)
    }

    pub fn revoke_package(
        &self,
        tenant: &TenantId,
        application_id: &ApplicationId,
        package_id: &PackageId,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        let record = s
            .packages
            .iter_mut()
            .find(|((app, _), p)| {
                app == application_id && &p.package_id == package_id && &p.tenant == tenant
            })
            .map(|(_, p)| p)
            .ok_or_else(not_found)?;
        record.status = PackageStatus::Revoked;
        s.audit.append(
            now,
            Some(tenant),
            "package.revoke",
            package_id.to_string(),
            true,
            "ok",
        );
        Ok(())
    }

    /// Creates a license. The returned id is the activation credential: keep
    /// it secret. It is never written to the audit log.
    pub fn create_license(
        &self,
        tenant: &TenantId,
        application_id: &ApplicationId,
        expires_at: Option<u64>,
        max_installations: u32,
        now: u64,
    ) -> Result<LicenseId, SersError> {
        if max_installations == 0 {
            return Err(SersError::InvalidInput("max_installations must be positive"));
        }
        let id = LicenseId::from_bytes(random_array::<16>()?);
        let mut s = self.lock();
        owned_app(&s, tenant, application_id)?;
        s.licenses.insert(
            id,
            License {
                tenant: tenant.clone(),
                application_id: application_id.clone(),
                status: LicenseStatus::Active,
                expires_at,
                max_installations,
                installations: HashSet::new(),
            },
        );
        s.audit.append(
            now,
            Some(tenant),
            "license.create",
            application_id.to_string(),
            true,
            "ok",
        );
        Ok(id)
    }

    pub fn set_license_status(
        &self,
        tenant: &TenantId,
        license: &LicenseId,
        status: LicenseStatus,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        let l = s
            .licenses
            .get_mut(license)
            .filter(|l| &l.tenant == tenant)
            .ok_or_else(not_found)?;
        l.status = status;
        let detail = match status {
            LicenseStatus::Active => "active",
            LicenseStatus::Suspended => "suspended",
            LicenseStatus::Revoked => "revoked",
        };
        s.audit
            .append(now, Some(tenant), "license.set_status", "license".to_owned(), true, detail);
        Ok(())
    }

    pub fn revoke_installation(
        &self,
        tenant: &TenantId,
        installation: &InstallationId,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        let inst = s
            .installations
            .get_mut(installation)
            .filter(|i| &i.tenant == tenant)
            .ok_or_else(not_found)?;
        inst.status = InstallationStatus::Revoked;
        s.audit.append(
            now,
            Some(tenant),
            "installation.revoke",
            installation.to_string(),
            true,
            "ok",
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Client-facing protocol
    // ------------------------------------------------------------------

    /// Registers an installation key after verifying proof of possession and
    /// the license. Idempotent for an already-active installation.
    pub fn register_installation(
        &self,
        req: &RegistrationRequest,
        license: &LicenseId,
        now: u64,
    ) -> Result<(), SersError> {
        let mut s = self.lock();
        let result = Self::register_installation_inner(&mut s, req, license, now);
        let tenant = s.apps.get(&req.application_id).map(|a| a.tenant.clone());
        let (allowed, detail) = match &result {
            Ok(()) => (true, "ok"),
            Err(_) => (false, "rejected"),
        };
        s.audit.append(
            now,
            tenant.as_ref(),
            "installation.register",
            req.installation_id.to_string(),
            allowed,
            detail,
        );
        result
    }

    fn register_installation_inner(
        s: &mut State,
        req: &RegistrationRequest,
        license_id: &LicenseId,
        now: u64,
    ) -> Result<(), SersError> {
        req.verify()?;
        let app = s
            .apps
            .get(&req.application_id)
            .ok_or(SersError::PolicyDenied("unknown application"))?;
        if app.status != AppStatus::Active {
            return Err(SersError::PolicyDenied("application disabled"));
        }
        let tenant = app.tenant.clone();
        if let Some(existing) = s.installations.get(&req.installation_id) {
            if existing.application_id == req.application_id
                && existing.status == InstallationStatus::Active
            {
                return Ok(());
            }
            return Err(SersError::PolicyDenied("installation cannot be registered"));
        }
        let license = s
            .licenses
            .get_mut(license_id)
            .ok_or(SersError::PolicyDenied("invalid license"))?;
        if license.application_id != req.application_id || !license_usable(license, now) {
            return Err(SersError::PolicyDenied("invalid license"));
        }
        if license.installations.len() >= license.max_installations as usize {
            return Err(SersError::PolicyDenied("license installation limit reached"));
        }
        license.installations.insert(req.installation_id);
        s.installations.insert(
            req.installation_id,
            Installation {
                tenant,
                application_id: req.application_id.clone(),
                public_key: req.public_key,
                license_id: *license_id,
                status: InstallationStatus::Active,
            },
        );
        Ok(())
    }

    /// Issues a challenge, but only to a registered, active installation of the
    /// named application (keeps the outstanding-challenge table from being
    /// filled by strangers).
    pub fn request_challenge(
        &self,
        req: &ChallengeRequest,
        now: u64,
    ) -> Result<Challenge, SersError> {
        {
            let s = self.lock();
            let known = s.installations.get(&req.installation_id).is_some_and(|i| {
                i.status == InstallationStatus::Active && i.application_id == req.application_id
            });
            if !known {
                return Err(SersError::PolicyDenied("unknown installation"));
            }
        }
        self.challenges.issue(req, now)
    }

    fn deny(
        s: &mut State,
        now: u64,
        tenant: Option<&TenantId>,
        subject: String,
        reason: DenyReason,
        detail: &'static str,
    ) -> Result<AuthorizationDecision, SersError> {
        s.audit.append(now, tenant, "authorize", subject, false, detail);
        Ok(AuthorizationDecision::Denied(reason))
    }

    /// Verifies a challenge response and decides. Order: signature and
    /// freshness (single-use challenge), installation, application, license,
    /// package, revocation and downgrade, attestation / policy, and only then
    /// key release.
    pub fn authorize(
        &self,
        response: &ChallengeResponse,
        claim: &ClientBackendClaim,
        evidence: Option<&AttestationEvidence>,
        now: u64,
    ) -> Result<AuthorizationDecision, SersError> {
        let mut s = self.lock();

        let verification = {
            let installations = &s.installations;
            self.challenges.verify_response(response, now, |id| {
                installations
                    .get(id)
                    .filter(|i| i.status == InstallationStatus::Active)
                    .map(|i| i.public_key)
            })
        };
        let verified = match verification {
            Ok(v) => v,
            Err(e) => {
                let (reason, detail) = match e {
                    SersError::ChallengeExpired => {
                        (DenyReason::InvalidChallenge, "challenge expired")
                    }
                    SersError::ChallengeUnknownOrReplayed => {
                        (DenyReason::InvalidChallenge, "challenge unknown or replayed")
                    }
                    SersError::SignatureInvalid => {
                        (DenyReason::InvalidChallenge, "invalid signature")
                    }
                    SersError::PolicyDenied(_) => {
                        (DenyReason::NotAuthorized, "installation not active")
                    }
                    _ => (DenyReason::InvalidChallenge, "invalid response"),
                };
                return Self::deny(&mut s, now, None, "unknown".to_owned(), reason, detail);
            }
        };
        let subject = verified.installation_id.to_string();

        let app_info = s.apps.get(&verified.application_id).map(|a| {
            (
                a.tenant.clone(),
                a.execution_policy,
                a.min_version_counter,
                a.status == AppStatus::Active,
            )
        });
        let Some((tenant, policy, min_counter, app_active)) = app_info else {
            return Self::deny(
                &mut s,
                now,
                None,
                subject,
                DenyReason::NotAuthorized,
                "unknown application",
            );
        };
        if !app_active {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "application disabled",
            );
        }

        let inst_info = s
            .installations
            .get(&verified.installation_id)
            .map(|i| (i.application_id.clone(), i.license_id, i.status));
        let Some((inst_app, license_id, inst_status)) = inst_info else {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "unknown installation",
            );
        };
        if inst_app != verified.application_id || inst_status != InstallationStatus::Active {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "installation not active",
            );
        }

        let license_ok = s
            .licenses
            .get(&license_id)
            .is_some_and(|l| l.application_id == verified.application_id && license_usable(l, now));
        if !license_ok {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "license not valid",
            );
        }

        let record = s
            .packages
            .get(&(verified.application_id.clone(), verified.package_digest))
            .map(|r| (r.package_id, r.status, r.version_counter, r.wrapped_key.clone()));
        let Some((package_id, package_status, counter, wrapped_key)) = record else {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "package not registered",
            );
        };
        if package_status != PackageStatus::Active {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "package revoked",
            );
        }
        if counter < min_counter {
            return Self::deny(
                &mut s,
                now,
                Some(&tenant),
                subject,
                DenyReason::NotAuthorized,
                "package version below minimum",
            );
        }

        // Policy. Hardware properties come from the attestation verifier only;
        // the client's claim can at most enable software placement.
        let outcome = self.attestation.verify(evidence, &verified.nonce);
        let caps = BackendCapabilities {
            process_isolation: claim.process_isolation,
            hardware_backed_confidentiality: outcome.hardware_backed,
            remote_attestation: outcome.hardware_backed,
            ..Default::default()
        };
        let placement = match decide_placement(policy, &caps, outcome.status) {
            Ok(ExecutionPlacement::Remote) => {
                s.audit.append(
                    now,
                    Some(&tenant),
                    "authorize",
                    subject,
                    true,
                    "remote execution only",
                );
                return Ok(AuthorizationDecision::RemoteOnly);
            }
            Ok(p) => p,
            Err(SersError::PolicyDenied(_)) => {
                return Self::deny(
                    &mut s,
                    now,
                    Some(&tenant),
                    subject,
                    DenyReason::HardwareAttestationRequired,
                    "hardware attestation required",
                );
            }
            Err(_) => {
                return Self::deny(
                    &mut s,
                    now,
                    Some(&tenant),
                    subject,
                    DenyReason::NotAuthorized,
                    "no usable execution backend",
                );
            }
        };

        // Key release: last step, only after every check passed.
        let package_key = self.keys.unwrap(
            &package_key_context(&verified.application_id, &package_id),
            &wrapped_key,
        )?;
        let ctx = KeyReleaseContext {
            nonce: &verified.nonce,
            application_id: &verified.application_id,
            installation_id: &verified.installation_id,
            package_digest: &verified.package_digest,
        };
        let key_release = seal_key_release(&ctx, &verified.client_ephemeral_key, &package_key)?;
        let token = AuthorizationToken {
            version: PROTOCOL_VERSION,
            token_id: Nonce32::from_bytes(random_array::<32>()?),
            application_id: verified.application_id.clone(),
            installation_id: verified.installation_id,
            package_digest: verified.package_digest,
            placement,
            issued_at: now,
            expires_at: now.saturating_add(self.config.authorization_ttl_secs),
        };
        let signature = self.signer.sign(&token.signing_bytes())?;
        s.audit.append(
            now,
            Some(&tenant),
            "key.release",
            subject.clone(),
            true,
            "package key released to authorized session",
        );
        s.audit
            .append(now, Some(&tenant), "authorize", subject, true, "granted");
        Ok(AuthorizationDecision::Granted(Grant {
            authorization: SignedAuthorization { token, signature },
            key_release,
        }))
    }
}
