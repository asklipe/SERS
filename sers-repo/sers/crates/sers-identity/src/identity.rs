use sers_core::{ApplicationId, InstallationId, PublicKeyBytes, SersError};
use sers_crypto::sign::SigningKeyPair;
use sers_protocol::{
    installation_id_from_public_key, Challenge, ChallengeResponse, RegistrationRequest,
    PROTOCOL_VERSION,
};
use zeroize::Zeroizing;

/// The cryptographic identity of one installation.
#[derive(Debug)]
pub struct InstallationIdentity {
    keypair: SigningKeyPair,
    id: InstallationId,
}

impl InstallationIdentity {
    pub fn generate() -> Result<Self, SersError> {
        Ok(Self::from_keypair(SigningKeyPair::generate()?))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_keypair(SigningKeyPair::from_seed(seed))
    }

    fn from_keypair(keypair: SigningKeyPair) -> Self {
        let id = installation_id_from_public_key(&keypair.public_key());
        Self { keypair, id }
    }

    pub fn id(&self) -> InstallationId {
        self.id
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        self.keypair.public_key()
    }

    /// Secret seed, for key stores only.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; 32]> {
        self.keypair.seed()
    }

    /// Builds the registration message including the proof of possession.
    pub fn registration_request(&self, application_id: &ApplicationId) -> RegistrationRequest {
        let public_key = self.public_key();
        let proof = self.keypair.sign(&RegistrationRequest::signing_bytes_for(
            application_id,
            &public_key,
            &self.id,
        ));
        RegistrationRequest {
            version: PROTOCOL_VERSION,
            application_id: application_id.clone(),
            public_key,
            installation_id: self.id,
            proof,
        }
    }

    /// Signs a server challenge. Refuses challenges addressed to another
    /// installation or using another protocol version. Expiry is enforced by
    /// the server, which owns the trusted clock.
    pub fn respond_to(&self, challenge: &Challenge) -> Result<ChallengeResponse, SersError> {
        if challenge.version != PROTOCOL_VERSION {
            return Err(SersError::Protocol("unsupported protocol version"));
        }
        if challenge.installation_id != self.id {
            return Err(SersError::Protocol(
                "challenge is addressed to another installation",
            ));
        }
        Ok(ChallengeResponse {
            version: PROTOCOL_VERSION,
            nonce: challenge.nonce,
            signature: self.keypair.sign(&challenge.signing_bytes()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sers_core::{Digest32, X25519PublicKey};
    use sers_protocol::{
        ChallengeAuthority, ChallengeRequest, InMemoryChallengeStore,
    };

    const NOW: u64 = 5_000;

    fn app() -> ApplicationId {
        ApplicationId::new("acme.editor").unwrap()
    }

    fn challenge_request(id: InstallationId) -> ChallengeRequest {
        ChallengeRequest {
            version: PROTOCOL_VERSION,
            application_id: app(),
            installation_id: id,
            package_digest: Digest32::from_bytes([5; 32]),
            client_ephemeral_key: X25519PublicKey::from_bytes([6; 32]),
        }
    }

    #[test]
    fn id_is_derived_from_public_key() {
        let identity = InstallationIdentity::generate().unwrap();
        assert_eq!(
            identity.id(),
            installation_id_from_public_key(&identity.public_key())
        );
    }

    #[test]
    fn same_seed_gives_same_identity() {
        let a = InstallationIdentity::generate().unwrap();
        let b = InstallationIdentity::from_seed(&a.seed());
        assert_eq!(a.id(), b.id());
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn registration_request_verifies() {
        let identity = InstallationIdentity::generate().unwrap();
        assert!(identity.registration_request(&app()).verify().is_ok());
    }

    #[test]
    fn refuses_challenge_for_another_installation() {
        let ours = InstallationIdentity::generate().unwrap();
        let other = InstallationIdentity::generate().unwrap();
        let authority =
            ChallengeAuthority::new(InMemoryChallengeStore::new(4), 60).unwrap();
        let challenge = authority
            .issue(&challenge_request(other.id()), NOW)
            .unwrap();
        assert!(ours.respond_to(&challenge).is_err());
    }

    #[test]
    fn end_to_end_challenge_response() {
        let identity = InstallationIdentity::generate().unwrap();
        let registration = identity.registration_request(&app());
        registration.verify().unwrap();
        let registered_key = registration.public_key;

        let authority =
            ChallengeAuthority::new(InMemoryChallengeStore::new(4), 60).unwrap();
        let challenge = authority
            .issue(&challenge_request(identity.id()), NOW)
            .unwrap();
        let response = identity.respond_to(&challenge).unwrap();
        let verified = authority
            .verify_response(&response, NOW + 1, |_| Some(registered_key))
            .unwrap();
        assert_eq!(verified.installation_id, identity.id());
    }

    #[test]
    fn debug_output_never_contains_secret_seed() {
        let identity = InstallationIdentity::generate().unwrap();
        let seed_hex: String = identity
            .seed()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!format!("{identity:?}").contains(&seed_hex));
    }
}
