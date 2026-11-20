//! Installation identity for the SERS client.
//!
//! * `identity` - Ed25519 installation key, derived installation id,
//!   registration proof-of-possession and challenge responses
//! * `keystore` - persistence of the installation key
//!
//! Hardware-backed keys (TPM 2.0, Secure Enclave, DPAPI/CNG) are **not**
//! implemented yet. The only store provided is a file store protected by OS
//! permissions, and it reports exactly that through [`KeyProtection`].

pub mod identity;
pub mod keystore;

pub use identity::InstallationIdentity;
pub use keystore::{load_or_create, FileKeyStore, KeyProtection, KeyStore};
