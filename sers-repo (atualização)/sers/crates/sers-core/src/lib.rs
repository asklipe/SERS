//! Shared vocabulary for SERS: errors, validated identifiers, fixed-size byte
//! newtypes (lowercase hex on the wire), backend capabilities and the
//! execution-placement decision.
//!
//! This crate has no cryptographic dependencies.

pub mod capabilities;
pub mod error;
pub mod ids;
pub mod policy;

pub use capabilities::{BackendCapabilities, TeeTechnology};
pub use error::SersError;
pub use ids::{
    ApplicationId, Digest32, InstallationId, LicenseId, ModuleId, Nonce32, PackageId,
    PublicKeyBytes, PublisherKeyId, SignatureBytes, TenantId, WrappedKey, X25519PublicKey,
};
pub use policy::{decide_placement, AttestationStatus, ExecutionPlacement, ExecutionPolicy};
