//! SERS wire protocol, version 1.
//!
//! * `message`       - versioned, strictly validated message types (JSON)
//! * `codec`         - size-limited decoding that rejects unknown fields/versions
//! * `signing`       - canonical, domain-separated bytes that get signed
//! * `authority`     - server-side challenge issuance and single-use verification
//! * `authorization` - short-lived, audience-bound signed grants
//! * `keyrelease`    - package-key delivery sealed to one authenticated session
//!
//! Freshness never relies on client clocks: the server keeps challenge state
//! and consumes it atomically on first use (replay protection).

pub mod authority;
pub mod authorization;
pub mod codec;
pub mod keyrelease;
pub mod message;
pub mod signing;

pub use authority::{
    ChallengeAuthority, ChallengeStore, InMemoryChallengeStore, VerifiedChallenge,
};
pub use authorization::{AuthorizationToken, SignedAuthorization, MAX_AUTHORIZATION_TTL_SECS};
pub use codec::{decode, encode, MAX_MESSAGE_BYTES};
pub use keyrelease::{open_key_release, seal_key_release, KeyRelease, KeyReleaseContext};
pub use message::{
    Challenge, ChallengeRequest, ChallengeResponse, ProtocolMessage, RegistrationRequest,
    PROTOCOL_VERSION,
};
pub use signing::installation_id_from_public_key;
