use crate::format::{FORMAT_VERSION, MAX_MODULES, MAX_MODULE_PLAINTEXT_BYTES};
use serde::{Deserialize, Serialize};
use sers_core::{
    ApplicationId, Digest32, ExecutionPolicy, ModuleId, PackageId, PublisherKeyId, SersError,
    WrappedKey,
};
use sers_crypto::aead::{NONCE_LEN, TAG_LEN};
use std::collections::HashSet;

/// One encrypted module. `wrapped_dek` is the module's data-encryption key
/// sealed under the package key, which only the Key Broker releases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleEntry {
    pub module_id: ModuleId,
    /// Module ABI the protected core implements (documented per ABI version).
    pub abi_version: u32,
    /// Offset into the data section.
    pub offset: u64,
    pub ciphertext_len: u64,
    pub plaintext_len: u64,
    pub ciphertext_sha256: Digest32,
    pub wrapped_dek: WrappedKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u16,
    pub package_id: PackageId,
    pub application_id: ApplicationId,
    pub publisher_key_id: PublisherKeyId,
    /// Human-readable version, e.g. `1.4.2`.
    pub version: String,
    /// Monotonic counter used for anti-downgrade decisions.
    pub version_counter: u64,
    pub created_at: u64,
    pub execution_policy: ExecutionPolicy,
    pub modules: Vec<ModuleEntry>,
}

pub(crate) fn validate_version_string(v: &str) -> Result<(), SersError> {
    if v.is_empty()
        || v.len() > 64
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(SersError::InvalidInput("invalid package version string"));
    }
    Ok(())
}

impl Manifest {
    /// Structural validation. `data_len` is the real size of the data section:
    /// module ranges must tile it exactly (no gaps, overlaps or trailing bytes).
    pub fn validate(&self, data_len: u64) -> Result<(), SersError> {
        if self.format_version != FORMAT_VERSION {
            return Err(SersError::Protocol("unsupported package format version"));
        }
        validate_version_string(&self.version)?;
        if self.modules.is_empty() || self.modules.len() > MAX_MODULES {
            return Err(SersError::InvalidInput("invalid number of modules"));
        }
        let overhead = (NONCE_LEN + TAG_LEN) as u64;
        let mut seen = HashSet::new();
        let mut cursor: u64 = 0;
        for m in &self.modules {
            if !seen.insert(m.module_id.as_str()) {
                return Err(SersError::InvalidInput("duplicate module id"));
            }
            if m.abi_version == 0 {
                return Err(SersError::InvalidInput("invalid module abi version"));
            }
            if m.plaintext_len > MAX_MODULE_PLAINTEXT_BYTES {
                return Err(SersError::InvalidInput("module exceeds size limit"));
            }
            let expected = m
                .plaintext_len
                .checked_add(overhead)
                .ok_or(SersError::InvalidInput("module length overflow"))?;
            if m.ciphertext_len != expected {
                return Err(SersError::InvalidInput("inconsistent module lengths"));
            }
            if m.offset != cursor {
                return Err(SersError::InvalidInput(
                    "module layout has gaps or overlaps",
                ));
            }
            cursor = cursor
                .checked_add(m.ciphertext_len)
                .ok_or(SersError::InvalidInput("module length overflow"))?;
        }
        if cursor != data_len {
            return Err(SersError::InvalidInput(
                "module data length does not match manifest",
            ));
        }
        Ok(())
    }
}
