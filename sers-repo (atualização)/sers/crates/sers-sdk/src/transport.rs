use sers_core::{LicenseId, SersError};
use sers_protocol::{
    Challenge, ChallengeRequest, ChallengeResponse, KeyRelease, RegistrationRequest,
    SignedAuthorization,
};

/// What the host tells the Control Plane about its own execution environment.
///
/// `process_isolation` is an unverifiable claim. Set it to `true` only if the
/// host really runs protected code in a separate process; the SDK defaults to
/// `false` and never claims hardware protection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientClaim {
    pub process_isolation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub authorization: SignedAuthorization,
    pub key_release: KeyRelease,
}

/// Coarse denial reasons, as returned by the Control Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyKind {
    InvalidChallenge,
    NotAuthorized,
    HardwareAttestationRequired,
}

impl DenyKind {
    pub(crate) fn message(self) -> &'static str {
        match self {
            DenyKind::InvalidChallenge => "authorization denied: invalid challenge",
            DenyKind::NotAuthorized => "authorization denied: not authorized",
            DenyKind::HardwareAttestationRequired => {
                "authorization denied: hardware attestation required"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Granted(Box<Grant>),
    /// The policy requires remote execution; no key is released.
    RemoteOnly,
    Denied(DenyKind),
}

/// Carries protocol messages to the Control Plane (HTTP over TLS in production).
/// Implementations must authenticate the server and must not retry
/// `authorize`: a challenge is single use.
pub trait Transport {
    fn register_installation(
        &self,
        request: &RegistrationRequest,
        license: &LicenseId,
    ) -> Result<(), SersError>;

    fn request_challenge(&self, request: &ChallengeRequest) -> Result<Challenge, SersError>;

    fn authorize(
        &self,
        response: &ChallengeResponse,
        claim: ClientClaim,
    ) -> Result<AuthorizationOutcome, SersError>;
}
