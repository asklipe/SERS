//! Centralized cryptographic abstraction for SERS.
//!
//! Only audited RustCrypto / dalek implementations are used; no primitive is
//! implemented here. Algorithms:
//!
//! * hashing: SHA-256
//! * signatures: Ed25519 (strict verification)
//! * key agreement: X25519 (low-order peer points rejected)
//! * key derivation: HKDF-SHA256
//! * AEAD: AES-256-GCM, random 96-bit nonce prepended to the ciphertext
//!
//! Secret material is wrapped in `Zeroizing` / `ZeroizeOnDrop` types.
//! Zeroization is best effort: it cannot reach copies made by the OS, swap,
//! or a debugger-privileged attacker.

pub mod aead;
pub mod hash;
pub mod kdf;
pub mod kex;
pub mod random;
pub mod secret;
pub mod sign;
