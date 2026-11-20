//! Short-lived authorization issued by the Control Plane and checked locally.

use crate::message::{ProtocolMessage, PROTOCOL_VERSION};
use crate::signing::push_len_prefixed;
use serde::{Deserialize, Serialize};
use sers_core::{
    ApplicationId, Digest32, ExecutionPlacement, InstallationId, Nonce32, PublicKeyBytes,
    SersError, SignatureBytes,
};
use sers_crypto::sign;

pub const MAX_AUTHORIZATION_TTL_SECS: u64 = 3600;
const DOMAIN_AUTHORIZATION: &[u8] = b"SERS-AUTHORIZATION-v1\0";

/// Audience-bound grant: valid for one application, one installation and one
/// package (manifest digest), until `expires_at` (server clock, Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationToken {
    pub version: u16,
    pub token_id: Nonce32,
    pub application_id: ApplicationId,
    pub installation_id: InstallationId,
    pub package_digest: Digest32,
    pub placement: ExecutionPlacement,
    pub issued_at: u64,
    pub expires_at: u64,
}

fn placement_code(p: ExecutionPlacement) -> u8 {
    match p {
        ExecutionPlacement::LocalSoftware => 1,
        ExecutionPlacement::LocalHardware => 2,
        ExecutionPlacement::Remote => 3,
    }
}

impl AuthorizationToken {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(192);
        buf.extend_from_slice(DOMAIN_AUTHORIZATION);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(self.token_id.as_bytes());
        push_len_prefixed(&mut buf, self.application_id.as_str().as_bytes());
        buf.extend_from_slice(self.installation_id.as_bytes());
        buf.extend_from_slice(self.package_digest.as_bytes());
        buf.push(placement_code(self.placement));
        buf.extend_from_slice(&self.issued_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub token: AuthorizationToken,
    pub signature: SignatureBytes,
}

impl ProtocolMessage for SignedAuthorization {
    fn version(&self) -> u16 {
        self.token.version
    }
}

impl SignedAuthorization {
    /// Checks version, lifetime bound, signature by the Control Plane's
    /// authorization key, audience and expiry (`now` is the local trusted clock;
    /// the runtime must also bound clock rollback).
    pub fn verify(
        &self,
        authority_key: &PublicKeyBytes,
        application_id: &ApplicationId,
        installation_id: &InstallationId,
        package_digest: &Digest32,
        now: u64,
    ) -> Result<&AuthorizationToken, SersError> {
        let t = &self.token;
        if t.version != PROTOCOL_VERSION {
            return Err(SersError::Protocol("unsupported protocol version"));
        }
        if t.expires_at <= t.issued_at || t.expires_at - t.issued_at > MAX_AUTHORIZATION_TTL_SECS {
            return Err(SersError::Protocol("invalid authorization lifetime"));
        }
        sign::verify(authority_key, &t.signing_bytes(), &self.signature)?;
        if &t.application_id != application_id
            || &t.installation_id != installation_id
            || &t.package_digest != package_digest
        {
            return Err(SersError::PolicyDenied("authorization audience mismatch"));
        }
        if now >= t.expires_at {
            return Err(SersError::PolicyDenied("authorization expired"));
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sers_crypto::sign::SigningKeyPair;

    const NOW: u64 = 10_000;

    fn token() -> AuthorizationToken {
        AuthorizationToken {
            version: PROTOCOL_VERSION,
            token_id: Nonce32::from_bytes([1; 32]),
            application_id: ApplicationId::new("acme.editor").unwrap(),
            installation_id: InstallationId::from_bytes([2; 32]),
            package_digest: Digest32::from_bytes([3; 32]),
            placement: ExecutionPlacement::LocalSoftware,
            issued_at: NOW,
            expires_at: NOW + 300,
        }
    }

    fn signed(kp: &SigningKeyPair, t: AuthorizationToken) -> SignedAuthorization {
        let signature = kp.sign(&t.signing_bytes());
        SignedAuthorization {
            token: t,
            signature,
        }
    }

    fn verify_default(s: &SignedAuthorization, key: &PublicKeyBytes, now: u64) -> Result<(), SersError> {
        let t = token();
        s.verify(key, &t.application_id, &t.installation_id, &t.package_digest, now)
            .map(|_| ())
    }

    #[test]
    fn valid_authorization_verifies() {
        let kp = SigningKeyPair::generate().unwrap();
        let s = signed(&kp, token());
        assert!(verify_default(&s, &kp.public_key(), NOW + 1).is_ok());
    }

    #[test]
    fn expired_authorization_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let s = signed(&kp, token());
        assert!(matches!(
            verify_default(&s, &kp.public_key(), NOW + 300),
            Err(SersError::PolicyDenied(_))
        ));
    }

    #[test]
    fn forged_or_tampered_authorization_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let other = SigningKeyPair::generate().unwrap();
        let s = signed(&other, token());
        assert_eq!(
            verify_default(&s, &kp.public_key(), NOW + 1),
            Err(SersError::SignatureInvalid)
        );
        let mut tampered = signed(&kp, token());
        tampered.token.expires_at += 10;
        assert_eq!(
            verify_default(&tampered, &kp.public_key(), NOW + 1),
            Err(SersError::SignatureInvalid)
        );
    }

    #[test]
    fn audience_mismatch_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let s = signed(&kp, token());
        let t = token();
        let other_installation = InstallationId::from_bytes([9; 32]);
        assert!(matches!(
            s.verify(&kp.public_key(), &t.application_id, &other_installation, &t.package_digest, NOW + 1),
            Err(SersError::PolicyDenied(_))
        ));
        let other_pkg = Digest32::from_bytes([9; 32]);
        assert!(matches!(
            s.verify(&kp.public_key(), &t.application_id, &t.installation_id, &other_pkg, NOW + 1),
            Err(SersError::PolicyDenied(_))
        ));
    }

    #[test]
    fn excessive_lifetime_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let mut t = token();
        t.expires_at = t.issued_at + MAX_AUTHORIZATION_TTL_SECS + 1;
        let s = signed(&kp, t);
        assert!(matches!(
            verify_default(&s, &kp.public_key(), NOW + 1),
            Err(SersError::Protocol(_))
        ));
    }

    #[test]
    fn placement_is_covered_by_the_signature() {
        let kp = SigningKeyPair::generate().unwrap();
        let mut s = signed(&kp, token());
        s.token.placement = ExecutionPlacement::LocalHardware;
        assert_eq!(
            verify_default(&s, &kp.public_key(), NOW + 1),
            Err(SersError::SignatureInvalid)
        );
    }
}
