use crate::format::{
    manifest_digest, module_aad, publisher_key_id_from_public_key, signing_input, wrap_aad,
    HEADER_LEN, MAGIC, MAX_MANIFEST_BYTES, MAX_PACKAGE_BYTES,
};
use crate::manifest::{Manifest, ModuleEntry};
use sers_core::{Digest32, ModuleId, PublicKeyBytes, PublisherKeyId, SersError, SignatureBytes};
use sers_crypto::{aead, hash::sha256, secret::SymmetricKey, sign};
use zeroize::Zeroizing;

/// A structurally parsed package whose signature has **not** been checked.
/// Nothing in it may be trusted, and the manifest is not even parsed yet.
pub struct RawPackage<'a> {
    publisher_key_id: PublisherKeyId,
    signature: SignatureBytes,
    manifest_bytes: &'a [u8],
    data: &'a [u8],
}

impl<'a> RawPackage<'a> {
    /// Checks magic and lengths only. Never allocates based on attacker-chosen sizes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, SersError> {
        if bytes.len() as u64 > MAX_PACKAGE_BYTES {
            return Err(SersError::InvalidInput("package too large"));
        }
        if bytes.len() < HEADER_LEN {
            return Err(SersError::InvalidInput("package truncated"));
        }
        if bytes[..8] != MAGIC[..] {
            return Err(SersError::InvalidInput("not a .sers package"));
        }
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&bytes[8..40]);
        let manifest_len =
            u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as usize;
        if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES {
            return Err(SersError::InvalidInput("invalid manifest length"));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes[44..HEADER_LEN]);
        let manifest_end = HEADER_LEN
            .checked_add(manifest_len)
            .ok_or(SersError::InvalidInput("invalid manifest length"))?;
        if bytes.len() < manifest_end {
            return Err(SersError::InvalidInput("package truncated"));
        }
        Ok(Self {
            publisher_key_id: PublisherKeyId::from_bytes(key_id),
            signature: SignatureBytes::from_bytes(sig),
            manifest_bytes: &bytes[HEADER_LEN..manifest_end],
            data: &bytes[manifest_end..],
        })
    }

    /// Claimed publisher key id; use it to look up a key you already trust.
    pub fn publisher_key_id(&self) -> PublisherKeyId {
        self.publisher_key_id
    }

    pub fn manifest_digest(&self) -> Digest32 {
        manifest_digest(self.manifest_bytes)
    }

    /// Verifies the signature with a trusted publisher key, *then* parses and
    /// validates the manifest.
    pub fn verify(self, publisher_key: &PublicKeyBytes) -> Result<VerifiedPackage<'a>, SersError> {
        if publisher_key_id_from_public_key(publisher_key) != self.publisher_key_id {
            return Err(SersError::PolicyDenied(
                "publisher key does not match package",
            ));
        }
        sign::verify(
            publisher_key,
            &signing_input(&self.publisher_key_id, self.manifest_bytes),
            &self.signature,
        )?;
        let manifest: Manifest = serde_json::from_slice(self.manifest_bytes)
            .map_err(|_| SersError::InvalidInput("malformed manifest"))?;
        if manifest.publisher_key_id != self.publisher_key_id {
            return Err(SersError::InvalidInput("manifest publisher mismatch"));
        }
        manifest.validate(self.data.len() as u64)?;
        Ok(VerifiedPackage {
            manifest,
            manifest_digest: manifest_digest(self.manifest_bytes),
            data: self.data,
        })
    }
}

/// A package whose manifest signature and structure are verified.
/// Module *contents* are verified by [`verify_integrity`](Self::verify_integrity)
/// and by authenticated decryption.
#[derive(Debug)]
pub struct VerifiedPackage<'a> {
    manifest: Manifest,
    manifest_digest: Digest32,
    data: &'a [u8],
}

impl<'a> VerifiedPackage<'a> {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    fn entry(&self, id: &ModuleId) -> Result<&ModuleEntry, SersError> {
        self.manifest
            .modules
            .iter()
            .find(|m| &m.module_id == id)
            .ok_or(SersError::InvalidInput("unknown module"))
    }

    fn ciphertext(&self, entry: &ModuleEntry) -> Result<&'a [u8], SersError> {
        let start = usize::try_from(entry.offset)
            .map_err(|_| SersError::InvalidInput("module range out of bounds"))?;
        let len = usize::try_from(entry.ciphertext_len)
            .map_err(|_| SersError::InvalidInput("module range out of bounds"))?;
        let end = start
            .checked_add(len)
            .ok_or(SersError::InvalidInput("module range out of bounds"))?;
        self.data
            .get(start..end)
            .ok_or(SersError::InvalidInput("module range out of bounds"))
    }

    /// Recomputes every module ciphertext hash and compares it with the signed manifest.
    pub fn verify_integrity(&self) -> Result<(), SersError> {
        for entry in &self.manifest.modules {
            let ct = self.ciphertext(entry)?;
            if sha256(ct) != *entry.ciphertext_sha256.as_bytes() {
                return Err(SersError::InvalidInput("module ciphertext hash mismatch"));
            }
        }
        Ok(())
    }

    fn unwrap_dek(
        &self,
        package_key: &SymmetricKey,
        entry: &ModuleEntry,
    ) -> Result<SymmetricKey, SersError> {
        let aad = wrap_aad(
            &self.manifest.package_id,
            &self.manifest.application_id,
            &entry.module_id,
        );
        let dek = aead::open(package_key, &aad, &entry.wrapped_dek.as_bytes()[..])?;
        if dek.len() != SymmetricKey::LEN {
            return Err(SersError::Crypto("wrapped key has wrong length"));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&dek);
        Ok(SymmetricKey::from_bytes(*bytes))
    }

    /// Confirms `package_key` unwraps every module key (used before the
    /// Control Plane accepts a package and its key).
    pub fn check_package_key(&self, package_key: &SymmetricKey) -> Result<(), SersError> {
        for entry in &self.manifest.modules {
            self.unwrap_dek(package_key, entry)?;
        }
        Ok(())
    }

    /// Decrypts one module. The plaintext is zeroized on drop; whoever holds
    /// it is inside the trust boundary of the selected backend.
    pub fn decrypt_module(
        &self,
        package_key: &SymmetricKey,
        id: &ModuleId,
    ) -> Result<Zeroizing<Vec<u8>>, SersError> {
        let entry = self.entry(id)?;
        let ct = self.ciphertext(entry)?;
        if sha256(ct) != *entry.ciphertext_sha256.as_bytes() {
            return Err(SersError::InvalidInput("module ciphertext hash mismatch"));
        }
        let dek = self.unwrap_dek(package_key, entry)?;
        let aad = module_aad(
            &self.manifest.package_id,
            &self.manifest.application_id,
            &entry.module_id,
            entry.plaintext_len,
            entry.abi_version,
        );
        let plaintext = aead::open(&dek, &aad, ct)?;
        if plaintext.len() as u64 != entry.plaintext_len {
            return Err(SersError::InvalidInput("module plaintext length mismatch"));
        }
        Ok(plaintext)
    }
}
