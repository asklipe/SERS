use serde::{Deserialize, Serialize};
use sers_core::{
    ApplicationId, Digest32, InstallationId, Nonce32, PublicKeyBytes, SignatureBytes,
    X25519PublicKey,
};

pub const PROTOCOL_VERSION: u16 = 1;

/// Implemented by every top-level message so the codec can enforce the version.
pub trait ProtocolMessage {
    fn version(&self) -> u16;
}

/// Client -> server: first registration of an installation key.
/// `proof` is a signature, by the new key, over `signing_bytes_for(..)`
/// (proof of possession).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub version: u16,
    pub application_id: ApplicationId,
    pub public_key: PublicKeyBytes,
    pub installation_id: InstallationId,
    pub proof: SignatureBytes,
}

/// Client -> server: ask for an authorization challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub version: u16,
    pub application_id: ApplicationId,
    pub installation_id: InstallationId,
    pub package_digest: Digest32,
    /// Fresh X25519 key of this session; the released package key is sealed to it.
    pub client_ephemeral_key: X25519PublicKey,
}

/// Server -> client: challenge bound to application, installation and package.
/// `issued_at` / `expires_at` are Unix seconds from the *server* clock and are
/// informational for the client; the server enforces expiry itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u16,
    pub nonce: Nonce32,
    pub application_id: ApplicationId,
    pub installation_id: InstallationId,
    pub package_digest: Digest32,
    pub client_ephemeral_key: X25519PublicKey,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Client -> server: signature over `Challenge::signing_bytes()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeResponse {
    pub version: u16,
    pub nonce: Nonce32,
    pub signature: SignatureBytes,
}

macro_rules! impl_versioned {
    ($($t:ty),*) => {
        $(impl ProtocolMessage for $t {
            fn version(&self) -> u16 { self.version }
        })*
    };
}

impl_versioned!(
    RegistrationRequest,
    ChallengeRequest,
    Challenge,
    ChallengeResponse
);
