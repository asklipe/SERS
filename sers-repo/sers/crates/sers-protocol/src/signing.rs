//! Canonical byte strings that are signed or hashed.
//!
//! JSON is *not* signed. Signed inputs are built from fixed-order, length-
//! prefixed binary fields with a distinct domain-separation tag per message
//! type and protocol version, so a signature made for one purpose can never
//! validate for another.

use crate::message::{Challenge, RegistrationRequest, PROTOCOL_VERSION};
use sers_core::{ApplicationId, InstallationId, PublicKeyBytes, SersError};
use sers_crypto::{hash::sha256_parts, sign};

const DOMAIN_CHALLENGE: &[u8] = b"SERS-AUTH-CHALLENGE-v1\0";
const DOMAIN_REGISTRATION: &[u8] = b"SERS-REGISTRATION-v1\0";
const DOMAIN_INSTALLATION_ID: &[u8] = b"SERS-INSTALLATION-ID-v1\0";

pub(crate) fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// `SHA-256(domain || public_key)`. An identifier, not a secret.
pub fn installation_id_from_public_key(public_key: &PublicKeyBytes) -> InstallationId {
    InstallationId::from_bytes(sha256_parts(&[
        DOMAIN_INSTALLATION_ID,
        &public_key.as_bytes()[..],
    ]))
}

impl Challenge {
    /// Bytes the client signs. Every field of the challenge is covered.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);
        buf.extend_from_slice(DOMAIN_CHALLENGE);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(self.nonce.as_bytes());
        push_len_prefixed(&mut buf, self.application_id.as_str().as_bytes());
        buf.extend_from_slice(self.installation_id.as_bytes());
        buf.extend_from_slice(self.package_digest.as_bytes());
        buf.extend_from_slice(self.client_ephemeral_key.as_bytes());
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf
    }
}

impl RegistrationRequest {
    pub fn signing_bytes_for(
        application_id: &ApplicationId,
        public_key: &PublicKeyBytes,
        installation_id: &InstallationId,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(DOMAIN_REGISTRATION);
        buf.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        push_len_prefixed(&mut buf, application_id.as_str().as_bytes());
        buf.extend_from_slice(public_key.as_bytes());
        buf.extend_from_slice(installation_id.as_bytes());
        buf
    }

    /// Server-side check: version, id derivation and proof of possession.
    /// Authorization to register (tenant, license) is a separate concern.
    pub fn verify(&self) -> Result<(), SersError> {
        if self.version != PROTOCOL_VERSION {
            return Err(SersError::Protocol("unsupported protocol version"));
        }
        if installation_id_from_public_key(&self.public_key) != self.installation_id {
            return Err(SersError::Protocol(
                "installation id does not match public key",
            ));
        }
        let bytes = Self::signing_bytes_for(
            &self.application_id,
            &self.public_key,
            &self.installation_id,
        );
        sign::verify(&self.public_key, &bytes, &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sers_crypto::sign::SigningKeyPair;

    fn app(s: &str) -> ApplicationId {
        ApplicationId::new(s).unwrap()
    }

    fn registration(kp: &SigningKeyPair, application: &ApplicationId) -> RegistrationRequest {
        let public_key = kp.public_key();
        let installation_id = installation_id_from_public_key(&public_key);
        let proof = kp.sign(&RegistrationRequest::signing_bytes_for(
            application,
            &public_key,
            &installation_id,
        ));
        RegistrationRequest {
            version: PROTOCOL_VERSION,
            application_id: application.clone(),
            public_key,
            installation_id,
            proof,
        }
    }

    #[test]
    fn valid_registration_verifies() {
        let kp = SigningKeyPair::generate().unwrap();
        assert!(registration(&kp, &app("acme.editor")).verify().is_ok());
    }

    #[test]
    fn registration_for_other_application_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let mut req = registration(&kp, &app("acme.editor"));
        req.application_id = app("acme.other");
        assert_eq!(req.verify(), Err(SersError::SignatureInvalid));
    }

    #[test]
    fn registration_with_mismatched_installation_id_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let mut req = registration(&kp, &app("acme.editor"));
        req.installation_id = InstallationId::from_bytes([9; 32]);
        assert!(matches!(req.verify(), Err(SersError::Protocol(_))));
    }

    #[test]
    fn registration_with_foreign_proof_is_rejected() {
        let owner = SigningKeyPair::generate().unwrap();
        let attacker = SigningKeyPair::generate().unwrap();
        let mut req = registration(&owner, &app("acme.editor"));
        // Attacker presents the victim's public key but signs with their own key.
        req.proof = attacker.sign(&RegistrationRequest::signing_bytes_for(
            &req.application_id,
            &req.public_key,
            &req.installation_id,
        ));
        assert_eq!(req.verify(), Err(SersError::SignatureInvalid));
    }

    #[test]
    fn installation_id_is_deterministic_and_key_dependent() {
        let a = SigningKeyPair::generate().unwrap();
        let b = SigningKeyPair::generate().unwrap();
        assert_eq!(
            installation_id_from_public_key(&a.public_key()),
            installation_id_from_public_key(&a.public_key())
        );
        assert_ne!(
            installation_id_from_public_key(&a.public_key()),
            installation_id_from_public_key(&b.public_key())
        );
    }
}
