use sers_core::{ApplicationId, Digest32, ModuleId, PackageId, PublicKeyBytes, PublisherKeyId};
use sers_crypto::hash::sha256_parts;

pub const MAGIC: &[u8; 8] = b"SERSPKG\x01";
pub const FORMAT_VERSION: u16 = 1;
/// magic (8) + publisher key id (32) + manifest length (4) + signature (64)
pub const HEADER_LEN: usize = 8 + 32 + 4 + 64;
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;
pub const MAX_MODULES: usize = 256;
pub const MAX_MODULE_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 1 << 30;

const DOMAIN_PACKAGE_SIGNATURE: &[u8] = b"SERS-PACKAGE-SIGNATURE-v1\0";
const DOMAIN_MANIFEST_DIGEST: &[u8] = b"SERS-MANIFEST-DIGEST-v1\0";
const DOMAIN_PUBLISHER_KEY_ID: &[u8] = b"SERS-PUBLISHER-KEY-ID-v1\0";
const DOMAIN_MODULE: &[u8] = b"SERS-MODULE-v1\0";
const DOMAIN_DEK_WRAP: &[u8] = b"SERS-DEK-WRAP-v1\0";

pub fn publisher_key_id_from_public_key(key: &PublicKeyBytes) -> PublisherKeyId {
    PublisherKeyId::from_bytes(sha256_parts(&[DOMAIN_PUBLISHER_KEY_ID, &key.as_bytes()[..]]))
}

/// Bytes covered by the publisher signature. The key id and the manifest
/// length are inside the signed input, so neither can be swapped.
pub(crate) fn signing_input(key_id: &PublisherKeyId, manifest: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN_PACKAGE_SIGNATURE.len() + 36 + manifest.len());
    buf.extend_from_slice(DOMAIN_PACKAGE_SIGNATURE);
    buf.extend_from_slice(key_id.as_bytes());
    buf.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    buf.extend_from_slice(manifest);
    buf
}

/// Digest that identifies a package towards the Control Plane. It covers the
/// signed manifest, which in turn commits to every module ciphertext hash.
pub(crate) fn manifest_digest(manifest_bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(sha256_parts(&[DOMAIN_MANIFEST_DIGEST, manifest_bytes]))
}

fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// AAD of a module ciphertext: binds it to package, application, module slot,
/// ABI and declared plaintext length.
pub(crate) fn module_aad(
    package_id: &PackageId,
    application_id: &ApplicationId,
    module_id: &ModuleId,
    plaintext_len: u64,
    abi_version: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(DOMAIN_MODULE);
    buf.extend_from_slice(package_id.as_bytes());
    push_len_prefixed(&mut buf, application_id.as_str().as_bytes());
    push_len_prefixed(&mut buf, module_id.as_str().as_bytes());
    buf.extend_from_slice(&plaintext_len.to_be_bytes());
    buf.extend_from_slice(&abi_version.to_be_bytes());
    buf
}

/// AAD used when a module key is wrapped under the package key.
pub(crate) fn wrap_aad(
    package_id: &PackageId,
    application_id: &ApplicationId,
    module_id: &ModuleId,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(DOMAIN_DEK_WRAP);
    buf.extend_from_slice(package_id.as_bytes());
    push_len_prefixed(&mut buf, application_id.as_str().as_bytes());
    push_len_prefixed(&mut buf, module_id.as_str().as_bytes());
    buf
}
