//! SERS Loader: turns `.sers` bytes into a [`VerifiedPackage`] only if the
//! publisher is trusted, the package is for the expected application, has not
//! been revoked, is not a downgrade, and its module hashes match.
//!
//! The trust store, minimum version counters and revocations held here are the
//! *local* view. The Control Plane remains authoritative for authorization and
//! key release; the loader just refuses obviously invalid packages early.
//! The loader never extracts anything to disk and never decrypts: decryption
//! needs a key that is only released to an authorized execution backend.

use sers_core::{
    decide_placement, ApplicationId, AttestationStatus, BackendCapabilities, ExecutionPlacement,
    PackageId, PublicKeyBytes, PublisherKeyId, SersError,
};
use sers_package::{publisher_key_id_from_public_key, Manifest, RawPackage, VerifiedPackage};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub struct Loader {
    trusted: HashMap<PublisherKeyId, PublicKeyBytes>,
    min_version_counters: HashMap<ApplicationId, u64>,
    revoked_packages: HashSet<PackageId>,
}

impl Loader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust_publisher(&mut self, key: PublicKeyBytes) -> PublisherKeyId {
        let id = publisher_key_id_from_public_key(&key);
        self.trusted.insert(id, key);
        id
    }

    pub fn set_min_version_counter(&mut self, application: ApplicationId, counter: u64) {
        let entry = self.min_version_counters.entry(application).or_insert(0);
        // The floor only ever rises: lowering it would re-open downgrades.
        *entry = (*entry).max(counter);
    }

    pub fn revoke_package(&mut self, package: PackageId) {
        self.revoked_packages.insert(package);
    }

    pub fn load<'a>(
        &self,
        bytes: &'a [u8],
        expected_application: &ApplicationId,
    ) -> Result<VerifiedPackage<'a>, SersError> {
        let raw = RawPackage::parse(bytes)?;
        let key = self
            .trusted
            .get(&raw.publisher_key_id())
            .ok_or(SersError::PolicyDenied("untrusted publisher"))?;
        let verified = raw.verify(key)?;
        let manifest = verified.manifest();
        if &manifest.application_id != expected_application {
            return Err(SersError::PolicyDenied(
                "package is for another application",
            ));
        }
        if self.revoked_packages.contains(&manifest.package_id) {
            return Err(SersError::PolicyDenied("package has been revoked"));
        }
        let floor = self
            .min_version_counters
            .get(&manifest.application_id)
            .copied()
            .unwrap_or(0);
        if manifest.version_counter < floor {
            return Err(SersError::PolicyDenied(
                "package version is below the minimum accepted",
            ));
        }
        verified.verify_integrity()?;
        Ok(verified)
    }
}

/// Where this package may run on a machine with the given *verified*
/// capabilities. Never downgrades `hardware_required` to software.
pub fn placement_for(
    manifest: &Manifest,
    capabilities: &BackendCapabilities,
    attestation: AttestationStatus,
) -> Result<ExecutionPlacement, SersError> {
    decide_placement(manifest.execution_policy, capabilities, attestation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sers_core::{ExecutionPolicy, ModuleId};
    use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};
    use sers_package::PackageBuilder;

    fn app() -> ApplicationId {
        ApplicationId::new("acme.editor").unwrap()
    }

    fn package(signer: &SigningKeyPair, counter: u64, policy: ExecutionPolicy) -> Vec<u8> {
        let key = SymmetricKey::generate().unwrap();
        let mut b = PackageBuilder::new(app(), "1.0.0", counter, policy, 1).unwrap();
        b.add_module(ModuleId::new("core").unwrap(), 1, vec![1, 2, 3])
            .unwrap();
        b.build(signer, &key).unwrap()
    }

    fn loader_trusting(signer: &SigningKeyPair) -> Loader {
        let mut l = Loader::new();
        l.trust_publisher(signer.public_key());
        l
    }

    #[test]
    fn trusted_package_loads() {
        let signer = SigningKeyPair::generate().unwrap();
        let bytes = package(&signer, 5, ExecutionPolicy::SoftwareAllowed);
        let v = loader_trusting(&signer).load(&bytes, &app()).unwrap();
        assert_eq!(v.manifest().version_counter, 5);
    }

    #[test]
    fn untrusted_publisher_is_rejected() {
        let signer = SigningKeyPair::generate().unwrap();
        let stranger = SigningKeyPair::generate().unwrap();
        let bytes = package(&stranger, 1, ExecutionPolicy::SoftwareAllowed);
        assert!(matches!(
            loader_trusting(&signer).load(&bytes, &app()),
            Err(SersError::PolicyDenied(_))
        ));
    }

    #[test]
    fn package_for_another_application_is_rejected() {
        let signer = SigningKeyPair::generate().unwrap();
        let bytes = package(&signer, 1, ExecutionPolicy::SoftwareAllowed);
        let other = ApplicationId::new("acme.other").unwrap();
        assert!(loader_trusting(&signer).load(&bytes, &other).is_err());
    }

    #[test]
    fn revoked_package_is_rejected() {
        let signer = SigningKeyPair::generate().unwrap();
        let bytes = package(&signer, 1, ExecutionPolicy::SoftwareAllowed);
        let mut l = loader_trusting(&signer);
        let id = l.load(&bytes, &app()).unwrap().manifest().package_id;
        l.revoke_package(id);
        assert!(l.load(&bytes, &app()).is_err());
    }

    #[test]
    fn downgrade_is_rejected_and_floor_never_lowers() {
        let signer = SigningKeyPair::generate().unwrap();
        let old = package(&signer, 3, ExecutionPolicy::SoftwareAllowed);
        let current = package(&signer, 4, ExecutionPolicy::SoftwareAllowed);
        let mut l = loader_trusting(&signer);
        l.set_min_version_counter(app(), 4);
        assert!(l.load(&old, &app()).is_err());
        assert!(l.load(&current, &app()).is_ok());
        l.set_min_version_counter(app(), 1);
        assert!(l.load(&old, &app()).is_err(), "floor must not be lowered");
    }

    #[test]
    fn tampered_module_data_is_rejected() {
        let signer = SigningKeyPair::generate().unwrap();
        let mut bytes = package(&signer, 1, ExecutionPolicy::SoftwareAllowed);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(loader_trusting(&signer).load(&bytes, &app()).is_err());
    }

    #[test]
    fn hardware_required_package_never_gets_software_placement() {
        let signer = SigningKeyPair::generate().unwrap();
        let bytes = package(&signer, 1, ExecutionPolicy::HardwareRequired);
        let l = loader_trusting(&signer);
        let v = l.load(&bytes, &app()).unwrap();
        let software = BackendCapabilities {
            process_isolation: true,
            ..Default::default()
        };
        assert!(placement_for(v.manifest(), &software, AttestationStatus::Verified).is_err());
    }
}
