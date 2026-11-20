use crate::message::{
    Challenge, ChallengeRequest, ChallengeResponse, PROTOCOL_VERSION,
};
use sers_core::{
    ApplicationId, Digest32, InstallationId, Nonce32, PublicKeyBytes, SersError,
    X25519PublicKey,
};
use sers_crypto::{random::random_array, sign};
use std::collections::HashMap;
use std::sync::Mutex;

/// Server-side storage of outstanding challenges.
///
/// `take` MUST be atomic and remove the entry (single use). A PostgreSQL
/// implementation should use `DELETE ... RETURNING`.
pub trait ChallengeStore: Send + Sync {
    fn insert(&self, challenge: Challenge, now: u64) -> Result<(), SersError>;
    fn take(&self, nonce: &Nonce32) -> Option<Challenge>;
}

/// Development / test store. Bounded to resist memory exhaustion.
pub struct InMemoryChallengeStore {
    max_outstanding: usize,
    inner: Mutex<HashMap<Nonce32, Challenge>>,
}

impl InMemoryChallengeStore {
    pub fn new(max_outstanding: usize) -> Self {
        Self {
            max_outstanding,
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl ChallengeStore for InMemoryChallengeStore {
    fn insert(&self, challenge: Challenge, now: u64) -> Result<(), SersError> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_outstanding {
            map.retain(|_, c| c.expires_at > now);
        }
        if map.len() >= self.max_outstanding {
            return Err(SersError::PolicyDenied("too many outstanding challenges"));
        }
        if map.contains_key(&challenge.nonce) {
            return Err(SersError::Protocol("duplicate nonce"));
        }
        map.insert(challenge.nonce, challenge);
        Ok(())
    }

    fn take(&self, nonce: &Nonce32) -> Option<Challenge> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(nonce)
    }
}

/// What the server learned from a successfully verified response.
///
/// Later authorization steps must use *these* values (the ones the challenge
/// was bound to), never values the client sends again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChallenge {
    pub nonce: Nonce32,
    pub application_id: ApplicationId,
    pub installation_id: InstallationId,
    pub package_digest: Digest32,
    pub client_ephemeral_key: X25519PublicKey,
}

pub struct ChallengeAuthority<S: ChallengeStore> {
    store: S,
    ttl_secs: u64,
}

impl<S: ChallengeStore> ChallengeAuthority<S> {
    pub const MAX_TTL_SECS: u64 = 300;

    pub fn new(store: S, ttl_secs: u64) -> Result<Self, SersError> {
        if ttl_secs == 0 || ttl_secs > Self::MAX_TTL_SECS {
            return Err(SersError::InvalidInput("challenge ttl out of range"));
        }
        Ok(Self { store, ttl_secs })
    }

    /// Issues a fresh 256-bit random challenge. `now` is the server clock
    /// in Unix seconds.
    pub fn issue(&self, request: &ChallengeRequest, now: u64) -> Result<Challenge, SersError> {
        if request.version != PROTOCOL_VERSION {
            return Err(SersError::Protocol("unsupported protocol version"));
        }
        let challenge = Challenge {
            version: PROTOCOL_VERSION,
            nonce: Nonce32::from_bytes(random_array::<32>()?),
            application_id: request.application_id.clone(),
            installation_id: request.installation_id,
            package_digest: request.package_digest,
            client_ephemeral_key: request.client_ephemeral_key,
            issued_at: now,
            expires_at: now.saturating_add(self.ttl_secs),
        };
        self.store.insert(challenge.clone(), now)?;
        Ok(challenge)
    }

    /// Verifies a response. The challenge is consumed *before* any other
    /// check, so every challenge gets exactly one verification attempt
    /// (replay protection; no oracle for repeated guessing).
    ///
    /// `lookup_key` resolves the registered public key of the installation the
    /// challenge was issued to. It MUST return `None` for unknown, suspended
    /// or revoked installations.
    pub fn verify_response<F>(
        &self,
        response: &ChallengeResponse,
        now: u64,
        lookup_key: F,
    ) -> Result<VerifiedChallenge, SersError>
    where
        F: FnOnce(&InstallationId) -> Option<PublicKeyBytes>,
    {
        if response.version != PROTOCOL_VERSION {
            return Err(SersError::Protocol("unsupported protocol version"));
        }
        let challenge = self
            .store
            .take(&response.nonce)
            .ok_or(SersError::ChallengeUnknownOrReplayed)?;
        if now >= challenge.expires_at {
            return Err(SersError::ChallengeExpired);
        }
        let key = lookup_key(&challenge.installation_id)
            .ok_or(SersError::PolicyDenied("installation is not active"))?;
        sign::verify(&key, &challenge.signing_bytes(), &response.signature)?;
        Ok(VerifiedChallenge {
            nonce: challenge.nonce,
            application_id: challenge.application_id,
            installation_id: challenge.installation_id,
            package_digest: challenge.package_digest,
            client_ephemeral_key: challenge.client_ephemeral_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::installation_id_from_public_key;
    use sers_crypto::sign::SigningKeyPair;

    const NOW: u64 = 1_000_000;

    struct Fixture {
        client: SigningKeyPair,
        id: InstallationId,
        authority: ChallengeAuthority<InMemoryChallengeStore>,
    }

    fn fixture_with_capacity(capacity: usize) -> Fixture {
        let client = SigningKeyPair::generate().unwrap();
        let id = installation_id_from_public_key(&client.public_key());
        let authority =
            ChallengeAuthority::new(InMemoryChallengeStore::new(capacity), 60).unwrap();
        Fixture {
            client,
            id,
            authority,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_capacity(8)
    }

    fn request(id: InstallationId) -> ChallengeRequest {
        ChallengeRequest {
            version: PROTOCOL_VERSION,
            application_id: ApplicationId::new("acme.editor").unwrap(),
            installation_id: id,
            package_digest: Digest32::from_bytes([7; 32]),
            client_ephemeral_key: X25519PublicKey::from_bytes([4; 32]),
        }
    }

    fn respond(client: &SigningKeyPair, c: &Challenge) -> ChallengeResponse {
        ChallengeResponse {
            version: PROTOCOL_VERSION,
            nonce: c.nonce,
            signature: client.sign(&c.signing_bytes()),
        }
    }

    #[test]
    fn issue_and_verify_succeeds() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        assert_eq!(c.expires_at, NOW + 60);
        let resp = respond(&f.client, &c);
        let key = f.client.public_key();
        let verified = f
            .authority
            .verify_response(&resp, NOW + 1, |_| Some(key))
            .unwrap();
        assert_eq!(verified.installation_id, f.id);
        assert_eq!(verified.application_id.as_str(), "acme.editor");
        assert_eq!(verified.package_digest, Digest32::from_bytes([7; 32]));
    }

    #[test]
    fn replayed_response_is_rejected() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        let resp = respond(&f.client, &c);
        let key = f.client.public_key();
        assert!(f
            .authority
            .verify_response(&resp, NOW + 1, |_| Some(key))
            .is_ok());
        assert_eq!(
            f.authority
                .verify_response(&resp, NOW + 2, |_| Some(key))
                .unwrap_err(),
            SersError::ChallengeUnknownOrReplayed
        );
    }

    #[test]
    fn expired_challenge_is_rejected_at_the_boundary() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        let resp = respond(&f.client, &c);
        let key = f.client.public_key();
        assert_eq!(
            f.authority
                .verify_response(&resp, NOW + 60, |_| Some(key))
                .unwrap_err(),
            SersError::ChallengeExpired
        );
    }

    #[test]
    fn last_valid_second_is_accepted() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        let resp = respond(&f.client, &c);
        let key = f.client.public_key();
        assert!(f
            .authority
            .verify_response(&resp, NOW + 59, |_| Some(key))
            .is_ok());
    }

    #[test]
    fn signature_by_wrong_key_is_rejected_and_challenge_is_consumed() {
        let f = fixture();
        let attacker = SigningKeyPair::generate().unwrap();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        let forged = respond(&attacker, &c);
        let registered = f.client.public_key();
        assert_eq!(
            f.authority
                .verify_response(&forged, NOW + 1, |_| Some(registered))
                .unwrap_err(),
            SersError::SignatureInvalid
        );
        // The legitimate client cannot retry on the same challenge either.
        let genuine = respond(&f.client, &c);
        assert_eq!(
            f.authority
                .verify_response(&genuine, NOW + 2, |_| Some(registered))
                .unwrap_err(),
            SersError::ChallengeUnknownOrReplayed
        );
    }

    #[test]
    fn signature_over_modified_challenge_is_rejected() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        // Client signs a challenge whose package digest was altered.
        let mut altered = c.clone();
        altered.package_digest = Digest32::from_bytes([8; 32]);
        let resp = ChallengeResponse {
            version: PROTOCOL_VERSION,
            nonce: c.nonce,
            signature: f.client.sign(&altered.signing_bytes()),
        };
        let key = f.client.public_key();
        assert_eq!(
            f.authority
                .verify_response(&resp, NOW + 1, |_| Some(key))
                .unwrap_err(),
            SersError::SignatureInvalid
        );
    }

    #[test]
    fn unknown_nonce_is_rejected() {
        let f = fixture();
        let resp = ChallengeResponse {
            version: PROTOCOL_VERSION,
            nonce: Nonce32::from_bytes([3; 32]),
            signature: f.client.sign(b"anything"),
        };
        let key = f.client.public_key();
        assert_eq!(
            f.authority
                .verify_response(&resp, NOW, |_| Some(key))
                .unwrap_err(),
            SersError::ChallengeUnknownOrReplayed
        );
    }

    #[test]
    fn inactive_installation_is_rejected() {
        let f = fixture();
        let c = f.authority.issue(&request(f.id), NOW).unwrap();
        let resp = respond(&f.client, &c);
        assert!(matches!(
            f.authority.verify_response(&resp, NOW + 1, |_| None),
            Err(SersError::PolicyDenied(_))
        ));
    }

    #[test]
    fn outstanding_challenges_are_bounded_and_expired_ones_are_purged() {
        let f = fixture_with_capacity(2);
        f.authority.issue(&request(f.id), NOW).unwrap();
        f.authority.issue(&request(f.id), NOW).unwrap();
        assert!(matches!(
            f.authority.issue(&request(f.id), NOW),
            Err(SersError::PolicyDenied(_))
        ));
        // After expiry, space is reclaimed.
        assert!(f.authority.issue(&request(f.id), NOW + 61).is_ok());
    }

    #[test]
    fn wrong_request_version_is_rejected() {
        let f = fixture();
        let mut req = request(f.id);
        req.version = 99;
        assert!(f.authority.issue(&req, NOW).is_err());
    }

    #[test]
    fn ttl_is_validated() {
        assert!(ChallengeAuthority::new(InMemoryChallengeStore::new(1), 0).is_err());
        assert!(ChallengeAuthority::new(InMemoryChallengeStore::new(1), 301).is_err());
        assert!(ChallengeAuthority::new(InMemoryChallengeStore::new(1), 300).is_ok());
    }

    #[test]
    fn nonces_are_unique_across_issues() {
        let f = fixture();
        let a = f.authority.issue(&request(f.id), NOW).unwrap();
        let b = f.authority.issue(&request(f.id), NOW).unwrap();
        assert_ne!(a.nonce, b.nonce);
    }
}
