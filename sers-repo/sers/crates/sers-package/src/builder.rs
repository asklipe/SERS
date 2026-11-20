use crate::format::{
    module_aad, publisher_key_id_from_public_key, signing_input, wrap_aad, FORMAT_VERSION,
    HEADER_LEN, MAGIC, MAX_MANIFEST_BYTES, MAX_MODULES, MAX_MODULE_PLAINTEXT_BYTES,
};
use crate::manifest::{validate_version_string, Manifest, ModuleEntry};
use sers_core::{ApplicationId, ExecutionPolicy, ModuleId, PackageId, SersError, WrappedKey};
use sers_crypto::{
    aead,
    hash::sha256,
    random::random_array,
    secret::SymmetricKey,
    sign::SigningKeyPair,
};
use sers_core::Digest32;
use zeroize::Zeroizing;

struct PendingModule {
    id: ModuleId,
    abi_version: u32,
    plaintext: Zeroizing<Vec<u8>>,
}

/// Builds a signed, encrypted `.sers` package.
///
/// Envelope encryption: each module gets a fresh random key (DEK); DEKs are
/// wrapped under `package_key`, which the caller obtains from / registers with
/// the Key Broker. The publisher's signing key never leaves the caller.
pub struct PackageBuilder {
    application_id: ApplicationId,
    version: String,
    version_counter: u64,
    execution_policy: ExecutionPolicy,
    created_at: u64,
    package_id: PackageId,
    modules: Vec<PendingModule>,
}

impl PackageBuilder {
    pub fn new(
        application_id: ApplicationId,
        version: &str,
        version_counter: u64,
        execution_policy: ExecutionPolicy,
        created_at: u64,
    ) -> Result<Self, SersError> {
        validate_version_string(version)?;
        Ok(Self {
            application_id,
            version: version.to_owned(),
            version_counter,
            execution_policy,
            created_at,
            package_id: PackageId::from_bytes(random_array::<16>()?),
            modules: Vec::new(),
        })
    }

    pub fn package_id(&self) -> PackageId {
        self.package_id
    }

    pub fn add_module(
        &mut self,
        id: ModuleId,
        abi_version: u32,
        plaintext: Vec<u8>,
    ) -> Result<(), SersError> {
        if abi_version == 0 {
            return Err(SersError::InvalidInput("invalid module abi version"));
        }
        if plaintext.len() as u64 > MAX_MODULE_PLAINTEXT_BYTES {
            return Err(SersError::InvalidInput("module exceeds size limit"));
        }
        if self.modules.len() >= MAX_MODULES {
            return Err(SersError::InvalidInput("too many modules"));
        }
        if self.modules.iter().any(|m| m.id == id) {
            return Err(SersError::InvalidInput("duplicate module id"));
        }
        self.modules.push(PendingModule {
            id,
            abi_version,
            plaintext: Zeroizing::new(plaintext),
        });
        Ok(())
    }

    pub fn build(
        self,
        signer: &SigningKeyPair,
        package_key: &SymmetricKey,
    ) -> Result<Vec<u8>, SersError> {
        if self.modules.is_empty() {
            return Err(SersError::InvalidInput("a package needs at least one module"));
        }
        let mut entries = Vec::with_capacity(self.modules.len());
        let mut data: Vec<u8> = Vec::new();
        for m in &self.modules {
            let plaintext_len = m.plaintext.len() as u64;
            let dek = SymmetricKey::generate()?;
            let aad = module_aad(
                &self.package_id,
                &self.application_id,
                &m.id,
                plaintext_len,
                m.abi_version,
            );
            let ciphertext = aead::seal(&dek, &aad, &m.plaintext)?;
            let wrapped = aead::seal(
                package_key,
                &wrap_aad(&self.package_id, &self.application_id, &m.id),
                dek.expose(),
            )?;
            let wrapped: [u8; WrappedKey::LEN] = wrapped
                .try_into()
                .map_err(|_| SersError::Crypto("unexpected wrapped key length"))?;
            entries.push(ModuleEntry {
                module_id: m.id.clone(),
                abi_version: m.abi_version,
                offset: data.len() as u64,
                ciphertext_len: ciphertext.len() as u64,
                plaintext_len,
                ciphertext_sha256: Digest32::from_bytes(sha256(&ciphertext)),
                wrapped_dek: WrappedKey::from_bytes(wrapped),
            });
            data.extend_from_slice(&ciphertext);
        }
        let manifest = Manifest {
            format_version: FORMAT_VERSION,
            package_id: self.package_id,
            application_id: self.application_id.clone(),
            publisher_key_id: publisher_key_id_from_public_key(&signer.public_key()),
            version: self.version.clone(),
            version_counter: self.version_counter,
            created_at: self.created_at,
            execution_policy: self.execution_policy,
            modules: entries,
        };
        manifest.validate(data.len() as u64)?;
        assemble(signer, &manifest, &data)
    }
}

/// Serializes and signs `manifest` and lays out the container. Exposed to the
/// crate so tests can produce *validly signed but malicious* manifests.
pub(crate) fn assemble(
    signer: &SigningKeyPair,
    manifest: &Manifest,
    data: &[u8],
) -> Result<Vec<u8>, SersError> {
    let manifest_bytes = serde_json::to_vec(manifest)
        .map_err(|_| SersError::Protocol("manifest serialization failed"))?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(SersError::InvalidInput("manifest too large"));
    }
    let key_id = publisher_key_id_from_public_key(&signer.public_key());
    let signature = signer.sign(&signing_input(&key_id, &manifest_bytes));
    let mut out = Vec::with_capacity(HEADER_LEN + manifest_bytes.len() + data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(key_id.as_bytes());
    out.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(signature.as_bytes());
    out.extend_from_slice(&manifest_bytes);
    out.extend_from_slice(data);
    Ok(out)
}
