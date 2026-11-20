//! The `.sers` protected package format, version 1.
//!
//! A package is a single binary container, **not** a ZIP/tar archive: modules
//! are addressed by id and byte range, never by path, and nothing is
//! decompressed, so path traversal, symlink and decompression-bomb attacks do
//! not exist by construction. See `docs/PACKAGE_FORMAT.md`.
//!
//! ```text
//! magic "SERSPKG\x01"            8 bytes
//! publisher_key_id               32 bytes  (SHA-256 of domain || public key)
//! manifest_len (u32, BE)         4 bytes   (<= 1 MiB)
//! signature (Ed25519)            64 bytes  over domain || key id || len || manifest
//! manifest (JSON, signed bytes)  manifest_len bytes
//! module data                    concatenated AES-256-GCM ciphertexts
//! ```
//!
//! The manifest is parsed only **after** its signature verified against a
//! publisher key the verifier already trusts.

pub mod builder;
pub mod format;
pub mod manifest;
pub mod reader;

#[cfg(test)]
mod tests;

pub use builder::PackageBuilder;
pub use format::{
    publisher_key_id_from_public_key, FORMAT_VERSION, HEADER_LEN, MAX_MANIFEST_BYTES,
    MAX_MODULES, MAX_MODULE_PLAINTEXT_BYTES, MAX_PACKAGE_BYTES,
};
pub use manifest::{Manifest, ModuleEntry};
pub use reader::{RawPackage, VerifiedPackage};
