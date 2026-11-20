use crate::clock::{Clock, MonotonicGuard, SystemClock};
use crate::transport::{AuthorizationOutcome, ClientClaim, Transport};
use sers_core::{
    ApplicationId, Digest32, ExecutionPlacement, InstallationId, LicenseId, ModuleId,
    PublicKeyBytes, PublisherKeyId, SersError, X25519PublicKey,
};
use sers_crypto::{kex::EphemeralKeyPair, secret::SymmetricKey};
use sers_identity::{load_or_create, InstallationIdentity, KeyStore};
use sers_loader::Loader;
use sers_package::{publisher_key_id_from_public_key, RawPackage};
use sers_protocol::{
    open_key_release, ChallengeRequest, KeyReleaseContext, SignedAuthorization, PROTOCOL_VERSION,
};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Collects the configuration of a [`SersApplication`].
#[derive(Default)]
pub struct SersApplicationBuilder {
    application_id: Option<ApplicationId>,
    license: Option<LicenseId>,
    identity: Option<InstallationIdentity>,
    key_store: Option<Box<dyn KeyStore>>,
    publishers: Vec<PublicKeyBytes>,
    authority_key: Option<PublicKeyBytes>,
    min_version_counter: u64,
    process_isolation: bool,
}

impl SersApplicationBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn application_id(mut self, id: ApplicationId) -> Self {
        self.application_id = Some(id);
        self
    }

    /// Activation credential of the license, obtained from the publisher.
    pub fn license(mut self, license: LicenseId) -> Self {
        self.license = Some(license);
        self
    }

    /// Publisher signing key this application trusts. At least one is required.
    pub fn trust_publisher(mut self, key: PublicKeyBytes) -> Self {
        self.publishers.push(key);
        self
    }

    /// Public key of the Control Plane's authorization signer.
    pub fn authority_key(mut self, key: PublicKeyBytes) -> Self {
        self.authority_key = Some(key);
        self
    }

    /// Use an identity you already hold. Exclusive with [`key_store`](Self::key_store).
    pub fn identity(mut self, identity: InstallationIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Load or create the identity in a key store. Exclusive with [`identity`](Self::identity).
    pub fn key_store(mut self, store: Box<dyn KeyStore>) -> Self {
        self.key_store = Some(store);
        self
    }

    /// Lowest package `version_counter` this application accepts.
    pub fn min_version_counter(mut self, counter: u64) -> Self {
        self.min_version_counter = counter;
        self
    }

    /// Declare that protected code runs in a separate process. The Control Plane
    /// cannot verify this claim. Leave it `false` unless it is true.
    pub fn claim_process_isolation(mut self, claim: bool) -> Self {
        self.process_isolation = claim;
        self
    }

    pub fn build<T: Transport>(
        self,
        transport: T,
    ) -> Result<SersApplication<T, SystemClock>, SersError> {
        self.build_with_clock(transport, SystemClock)
    }

    pub fn build_with_clock<T: Transport, C: Clock>(
        self,
        transport: T,
        clock: C,
    ) -> Result<SersApplication<T, C>, SersError> {
        let application_id = self
            .application_id
            .ok_or(SersError::InvalidInput("application id is required"))?;
        let license = self
            .license
            .ok_or(SersError::InvalidInput("license is required"))?;
        let authority_key = self
            .authority_key
            .ok_or(SersError::InvalidInput("authority key is required"))?;
        if self.publishers.is_empty() {
            return Err(SersError::InvalidInput(
                "at least one trusted publisher is required",
            ));
        }
        let identity = match (self.identity, self.key_store) {
            (Some(identity), None) => identity,
            (None, Some(store)) => load_or_create(store.as_ref())?,
            (None, None) => {
                return Err(SersError::InvalidInput(
                    "an identity or a key store is required",
                ))
            }
            (Some(_), Some(_)) => {
                return Err(SersError::InvalidInput(
                    "provide either an identity or a key store, not both",
                ))
            }
        };
        let mut loader = Loader::new();
        let mut publishers = HashMap::new();
        for key in self.publishers {
            let id = loader.trust_publisher(key);
            publishers.insert(id, key);
        }
        loader.set_min_version_counter(application_id.clone(), self.min_version_counter);
        Ok(SersApplication {
            application_id,
            license,
            identity,
            loader,
            publishers,
            authority_key,
            claim: ClientClaim {
                process_isolation: self.process_isolation,
            },
            transport,
            clock,
            guard: MonotonicGuard::default(),
        })
    }
}

/// A protected application on this machine.
pub struct SersApplication<T: Transport, C: Clock = SystemClock> {
    application_id: ApplicationId,
    license: LicenseId,
    identity: InstallationIdentity,
    loader: Loader,
    publishers: HashMap<PublisherKeyId, PublicKeyBytes>,
    authority_key: PublicKeyBytes,
    claim: ClientClaim,
    transport: T,
    clock: C,
    guard: MonotonicGuard,
}

impl<T: Transport, C: Clock> SersApplication<T, C> {
    pub fn installation_id(&self) -> InstallationId {
        self.identity.id()
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// Registers this installation with the Control Plane (proof of possession
    /// plus license). Idempotent for an installation that is still active.
    pub fn initialize(&self) -> Result<(), SersError> {
        let request = self.identity.registration_request(&self.application_id);
        self.transport
            .register_installation(&request, &self.license)
    }

    fn trusted_now(&self) -> Result<u64, SersError> {
        self.guard.observe(self.clock.now())
    }

    /// Verifies `package`, obtains an authorization and the sealed package key,
    /// and returns a handle from which modules can be decrypted until the
    /// authorization expires.
    pub fn open(&self, package: Vec<u8>) -> Result<OpenedPackage, SersError> {
        let raw = RawPackage::parse(&package)?;
        let publisher_key = *self
            .publishers
            .get(&raw.publisher_key_id())
            .ok_or(SersError::PolicyDenied("untrusted publisher"))?;
        let package_digest = {
            let verified = self.loader.load(&package, &self.application_id)?;
            verified.manifest_digest()
        };

        let ephemeral = EphemeralKeyPair::generate();
        let request = ChallengeRequest {
            version: PROTOCOL_VERSION,
            application_id: self.application_id.clone(),
            installation_id: self.identity.id(),
            package_digest,
            client_ephemeral_key: X25519PublicKey::from_bytes(ephemeral.public_key()),
        };
        let challenge = self.transport.request_challenge(&request)?;
        if challenge.application_id != request.application_id
            || challenge.installation_id != request.installation_id
            || challenge.package_digest != request.package_digest
            || challenge.client_ephemeral_key != request.client_ephemeral_key
        {
            return Err(SersError::Protocol("challenge does not match the request"));
        }
        let response = self.identity.respond_to(&challenge)?;

        let grant = match self.transport.authorize(&response, self.claim)? {
            AuthorizationOutcome::Granted(grant) => *grant,
            AuthorizationOutcome::RemoteOnly => {
                return Err(SersError::Unsupported(
                    "remote execution is not implemented in this SDK",
                ))
            }
            AuthorizationOutcome::Denied(kind) => {
                return Err(SersError::PolicyDenied(kind.message()))
            }
        };

        let installation_id = self.identity.id();
        let now = self.trusted_now()?;
        let token = grant.authorization.verify(
            &self.authority_key,
            &self.application_id,
            &installation_id,
            &package_digest,
            now,
        )?;
        if !matches!(
            token.placement,
            ExecutionPlacement::LocalSoftware | ExecutionPlacement::LocalHardware
        ) {
            return Err(SersError::Protocol(
                "authorization does not grant local execution",
            ));
        }

        let ctx = KeyReleaseContext {
            nonce: &challenge.nonce,
            application_id: &self.application_id,
            installation_id: &installation_id,
            package_digest: &package_digest,
        };
        let package_key = open_key_release(&ctx, ephemeral, &grant.key_release)?;
        RawPackage::parse(&package)?
            .verify(&publisher_key)?
            .check_package_key(&package_key)?;

        Ok(OpenedPackage {
            package,
            package_digest,
            publisher_key,
            package_key,
            authorization: grant.authorization,
        })
    }

    /// Decrypts one module. Fails once the authorization has expired or if the
    /// system clock was moved backwards. The plaintext is zeroized on drop.
    pub fn module(
        &self,
        opened: &OpenedPackage,
        id: &ModuleId,
    ) -> Result<Zeroizing<Vec<u8>>, SersError> {
        let now = self.trusted_now()?;
        let token = &opened.authorization.token;
        if token.application_id != self.application_id
            || token.installation_id != self.identity.id()
        {
            return Err(SersError::PolicyDenied(
                "package was opened by another application or installation",
            ));
        }
        if now >= token.expires_at {
            return Err(SersError::PolicyDenied("authorization expired"));
        }
        RawPackage::parse(&opened.package)?
            .verify(&opened.publisher_key)?
            .decrypt_module(&opened.package_key, id)
    }
}

/// A package that was verified and authorized. Holds the package key; drop it
/// when done.
pub struct OpenedPackage {
    package: Vec<u8>,
    package_digest: Digest32,
    publisher_key: PublicKeyBytes,
    package_key: SymmetricKey,
    authorization: SignedAuthorization,
}

impl OpenedPackage {
    /// End of the authorization, in Unix seconds (server clock).
    pub fn expires_at(&self) -> u64 {
        self.authorization.token.expires_at
    }

    pub fn package_digest(&self) -> Digest32 {
        self.package_digest
    }

    pub fn module_ids(&self) -> Result<Vec<ModuleId>, SersError> {
        let verified = RawPackage::parse(&self.package)?.verify(&self.publisher_key)?;
        Ok(verified
            .manifest()
            .modules
            .iter()
            .map(|m| m.module_id.clone())
            .collect())
    }
}

impl core::fmt::Debug for OpenedPackage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedPackage")
            .field("package_digest", &self.package_digest)
            .field("expires_at", &self.expires_at())
            .field("package_key", &"<redacted>")
            .finish()
    }
}

/// Key id of a publisher key, as embedded in packages.
pub fn publisher_id(key: &PublicKeyBytes) -> PublisherKeyId {
    publisher_key_id_from_public_key(key)
}
