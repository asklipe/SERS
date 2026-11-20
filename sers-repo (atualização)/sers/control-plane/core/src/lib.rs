//! SERS Control Plane core: the authorization logic, independent of transport
//! and storage.
//!
//! One crate with one module per service (see ADR 0003): tenants and API keys,
//! applications, packages, installations, licenses, challenge-response
//! authorization, Key Broker, revocation and audit. State is held **in
//! memory** (dev/test). The HTTP gateway and the PostgreSQL store are not
//! implemented yet; `control-plane/migrations` only defines the target schema.
//!
//! Security properties enforced here and covered by `tests/flow.rs`:
//! tenant isolation, proof of possession, single-use challenges, license /
//! installation / package / application revocation, anti-downgrade, no key
//! release without an explicit grant, and fail-closed hardware policy.

pub mod attestation;
pub mod audit;
pub mod keys;
pub mod service;
mod state;

pub use attestation::{
    AttestationEvidence, AttestationOutcome, AttestationVerifier, UnsupportedAttestationVerifier,
};
pub use audit::{AuditEvent, AuditLog};
pub use keys::{KeyProvider, LocalDevKeyProvider, TokenSigner};
pub use service::{
    AuthorizationDecision, ClientBackendClaim, ControlPlane, ControlPlaneConfig, DenyReason, Grant,
};
pub use state::LicenseStatus;
