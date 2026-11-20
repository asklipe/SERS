use thiserror::Error;

/// Error type shared by all SERS crates.
///
/// Messages are static strings on purpose: they must never embed key
/// material, plaintext or attacker-controlled data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SersError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("cryptographic operation failed: {0}")]
    Crypto(&'static str),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("challenge expired")]
    ChallengeExpired,
    #[error("challenge unknown or already used")]
    ChallengeUnknownOrReplayed,
    #[error("denied by policy: {0}")]
    PolicyDenied(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("i/o error: {0}")]
    Io(String),
}

impl From<std::io::Error> for SersError {
    fn from(e: std::io::Error) -> Self {
        SersError::Io(e.to_string())
    }
}
