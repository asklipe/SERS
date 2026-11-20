use serde::Deserialize;
use serde_json::{json, Value};
use sers_core::{ApplicationId, ExecutionPolicy, ModuleId, PublicKeyBytes};
use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};
use sers_identity::{load_or_create, FileKeyStore, InstallationIdentity, KeyStore};
use sers_package::{
    PackageBuilder, RawPackage, MAX_MODULES, MAX_MODULE_PLAINTEXT_BYTES, MAX_PACKAGE_BYTES,
};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_BUILD_CONFIG_BYTES: u64 = 1 << 20;
const MAX_CLI_BUILD_PLAINTEXT_BYTES: u64 = 256 * 1024 * 1024;

/// Read no more than the format's documented maximum plus one byte, so a file
/// that grows after metadata is checked cannot cause an unbounded read.
pub fn read_package(path: &Path) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path).map_err(|_| "could not open package file")?;
    let size = file
        .metadata()
        .map_err(|_| "could not read package metadata")?
        .len();
    if size > MAX_PACKAGE_BYTES {
        return Err("package exceeds the SERS size limit".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read package file")?;
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err("package exceeds the SERS size limit".to_owned());
    }
    Ok(bytes)
}

/// Show only header claims until the caller supplies a trusted publisher key.
/// The signed manifest is not parsed or returned in the unverified case.
pub fn inspect_bytes(
    bytes: &[u8],
    publisher_key: Option<&PublicKeyBytes>,
) -> Result<Value, String> {
    let raw = RawPackage::parse(bytes).map_err(|error| error.to_string())?;
    let publisher_key_id = raw.publisher_key_id().to_string();
    let manifest_digest = raw.manifest_digest().to_string();
    let base = json!({
        "package_size_bytes": bytes.len(),
        "publisher_key_id": publisher_key_id,
        "manifest_digest": manifest_digest,
    });

    match publisher_key {
        None => Ok(json!({
            "status": "unverified",
            "signature_verified": false,
            "integrity_verified": false,
            "manifest_available": false,
            "package": base,
            "next_step": "rerun with --publisher-key <trusted-lowercase-hex-key>",
        })),
        Some(key) => {
            let verified = raw.verify(key).map_err(|error| error.to_string())?;
            verified
                .verify_integrity()
                .map_err(|error| error.to_string())?;
            let manifest = serde_json::to_value(verified.manifest())
                .map_err(|_| "could not serialize verified manifest")?;
            Ok(json!({
                "status": "verified",
                "signature_verified": true,
                "integrity_verified": true,
                "manifest_available": true,
                "package": base,
                "manifest": manifest,
            }))
        }
    }
}

pub fn backend_report() -> Result<Value, String> {
    let report = sers_platform::detect();
    let backends = sers_platform::backends(&report);
    serde_json::to_value(json!({ "report": report, "backends": backends }))
        .map_err(|_| "could not serialize backend report".to_owned())
}

pub fn parse_public_key(hex: &str) -> Result<PublicKeyBytes, String> {
    PublicKeyBytes::from_str(hex).map_err(|error| error.to_string())
}

fn identity_summary(identity: &InstallationIdentity, store: &dyn KeyStore) -> Value {
    let protection = match store.protection() {
        sers_identity::KeyProtection::OsFilePermissionsOnly => "os_file_permissions_only",
        sers_identity::KeyProtection::Unsupported => "unsupported",
    };
    json!({
        "status": "ready",
        "installation_id": identity.id().to_string(),
        "public_key": identity.public_key().to_string(),
        "key_protection": protection,
    })
}

/// Create or load an installation identity without exposing its private seed.
/// The configured platform keystore determines whether persistence is supported.
pub fn identity_init(path: &Path) -> Result<Value, String> {
    let store = FileKeyStore::new(path);
    let identity = load_or_create(&store).map_err(|_| {
        "could not initialize identity; this platform may not support the file keystore".to_owned()
    })?;
    Ok(identity_summary(&identity, &store))
}

pub fn identity_show(path: &Path) -> Result<Value, String> {
    let store = FileKeyStore::new(path);
    let identity = store
        .load()
        .map_err(|_| "could not read installation identity".to_owned())?
        .ok_or_else(|| "installation identity was not found".to_owned())?;
    Ok(identity_summary(&identity, &store))
}

pub fn identity_registration_request(path: &Path, application_id: &str) -> Result<Value, String> {
    let application_id = ApplicationId::new(application_id.to_owned())
        .map_err(|_| "invalid application id".to_owned())?;
    let store = FileKeyStore::new(path);
    let identity = store
        .load()
        .map_err(|_| "could not read installation identity".to_owned())?
        .ok_or_else(|| "installation identity was not found".to_owned())?;
    let request = identity.registration_request(&application_id);
    Ok(json!({
        "status": "generated",
        "registration_request": request,
        "key_protection": identity_summary(&identity, &store)["key_protection"],
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageBuildConfig {
    application_id: String,
    version: String,
    version_counter: u64,
    execution_policy: ExecutionPolicy,
    #[serde(default)]
    created_at: Option<u64>,
    signing_seed_file: PathBuf,
    package_key_file: PathBuf,
    modules: Vec<ModuleSource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleSource {
    module_id: String,
    abi_version: u32,
    file: PathBuf,
}

fn resolve_from(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn read_secret_32(path: &Path, message: &'static str) -> Result<Zeroizing<[u8; 32]>, String> {
    let file = File::open(path).map_err(|_| message.to_owned())?;
    if !file.metadata().map_err(|_| message.to_owned())?.is_file() {
        return Err(message.to_owned());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(33));
    file.take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| message.to_owned())?;
    if bytes.len() != 32 {
        return Err("key files must contain exactly 32 raw bytes".to_owned());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn read_module(path: &Path, total: &mut u64) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(path).map_err(|_| "could not open a module file")?;
    let size = file
        .metadata()
        .map_err(|_| "could not read module metadata")?
        .len();
    if size > MAX_MODULE_PLAINTEXT_BYTES {
        return Err("a module exceeds the SERS size limit".to_owned());
    }
    *total = total
        .checked_add(size)
        .ok_or_else(|| "package input size overflow".to_owned())?;
    if *total > MAX_CLI_BUILD_PLAINTEXT_BYTES {
        return Err("CLI package builds are limited to 256 MiB of plaintext".to_owned());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
    file.take(MAX_MODULE_PLAINTEXT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "could not read a module file")?;
    if bytes.len() as u64 > MAX_MODULE_PLAINTEXT_BYTES || bytes.len() as u64 != size {
        return Err("module size changed or exceeds the SERS size limit".to_owned());
    }
    Ok(bytes)
}

fn write_new_package(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > MAX_PACKAGE_BYTES {
        return Err("package exceeds the SERS size limit".to_owned());
    }
    path.file_name()
        .ok_or_else(|| "package output path must name a file".to_owned())?;
    // create_new makes the existence check and creation atomic, so concurrent
    // invocations cannot overwrite a package. It works on filesystems where
    // hard links are unavailable. A crash during the write can leave a partial
    // file, which the user can remove before retrying.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "package output already exists or cannot be created".to_owned())?;
    let written = file.write_all(bytes).and_then(|_| file.sync_all());
    drop(file);
    if written.is_err() {
        return Err("could not write package output".to_owned());
    }
    Ok(())
}

/// Builds a package from a strict JSON config. Key files are raw 32-byte
/// secrets; callers must protect their access using the host OS or a secret
/// manager. The CLI never writes secret files or prints their contents.
pub fn build_package_from_config(config_path: &Path, output_path: &Path) -> Result<Value, String> {
    let config_file = File::open(config_path).map_err(|_| "could not open package config")?;
    let config_size = config_file
        .metadata()
        .map_err(|_| "could not read package config metadata")?
        .len();
    if config_size > MAX_BUILD_CONFIG_BYTES {
        return Err("package config exceeds the 1 MiB limit".to_owned());
    }
    let mut config_bytes = Vec::with_capacity(config_size as usize);
    config_file
        .take(MAX_BUILD_CONFIG_BYTES + 1)
        .read_to_end(&mut config_bytes)
        .map_err(|_| "could not read package config")?;
    if config_bytes.len() as u64 > MAX_BUILD_CONFIG_BYTES {
        return Err("package config exceeds the 1 MiB limit".to_owned());
    }
    let config: PackageBuildConfig = serde_json::from_slice(&config_bytes)
        .map_err(|_| "package config is invalid JSON or has unsupported fields")?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    let seed_path = resolve_from(base, &config.signing_seed_file);
    let package_key_path = resolve_from(base, &config.package_key_file);
    let seed = read_secret_32(&seed_path, "could not read publisher signing seed")?;
    let package_key_bytes = read_secret_32(&package_key_path, "could not read package key")?;
    let signer = SigningKeyPair::from_seed(&seed);
    let package_key = SymmetricKey::from_bytes(*package_key_bytes);

    let application_id =
        ApplicationId::new(config.application_id).map_err(|_| "invalid application id")?;
    let created_at = match config.created_at {
        Some(value) => value,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?
            .as_secs(),
    };
    let mut builder = PackageBuilder::new(
        application_id,
        &config.version,
        config.version_counter,
        config.execution_policy,
        created_at,
    )
    .map_err(|_| "invalid package metadata")?;

    if config.modules.is_empty() || config.modules.len() > MAX_MODULES {
        return Err("package config must include 1 to 256 modules".to_owned());
    }
    let mut total = 0;
    let mut seen_modules = HashSet::with_capacity(config.modules.len());
    for module in config.modules {
        let id = ModuleId::new(module.module_id).map_err(|_| "invalid module id")?;
        if module.abi_version == 0 {
            return Err("invalid module ABI version".to_owned());
        }
        if !seen_modules.insert(id.clone()) {
            return Err("duplicate module id".to_owned());
        }
        let source_path = resolve_from(base, &module.file);
        let mut plaintext = read_module(&source_path, &mut total)?;
        builder
            .add_module(id, module.abi_version, std::mem::take(&mut *plaintext))
            .map_err(|_| "invalid module metadata")?;
    }

    let bytes = builder
        .build(&signer, &package_key)
        .map_err(|_| "could not build signed package")?;
    let verified = RawPackage::parse(&bytes)
        .and_then(|package| package.verify(&signer.public_key()))
        .map_err(|_| "built package failed signature verification")?;
    verified
        .verify_integrity()
        .map_err(|_| "built package failed integrity verification")?;
    let package_id = verified.manifest().package_id.to_string();
    let publisher_key_id = verified.manifest().publisher_key_id.to_string();
    write_new_package(output_path, &bytes)?;

    Ok(json!({
        "status": "built",
        "package_id": package_id,
        "publisher_key_id": publisher_key_id,
        "publisher_public_key": signer.public_key().to_string(),
        "package_size_bytes": bytes.len(),
        "output": output_path.display().to_string(),
        "signature_verified": true,
        "integrity_verified": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sers_core::{ApplicationId, ExecutionPolicy, ModuleId};
    use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};
    use sers_package::PackageBuilder;

    fn fixture() -> (Vec<u8>, SigningKeyPair) {
        let signer = SigningKeyPair::generate().unwrap();
        let key = SymmetricKey::generate().unwrap();
        let mut builder = PackageBuilder::new(
            ApplicationId::new("acme.editor").unwrap(),
            "1.0.0",
            1,
            ExecutionPolicy::SoftwareAllowed,
            1,
        )
        .unwrap();
        builder
            .add_module(ModuleId::new("core").unwrap(), 1, b"secret module".to_vec())
            .unwrap();
        (builder.build(&signer, &key).unwrap(), signer)
    }

    #[test]
    fn unverified_inspection_never_exposes_manifest() {
        let (bytes, _) = fixture();
        let result = inspect_bytes(&bytes, None).unwrap();
        assert_eq!(result["signature_verified"], false);
        assert_eq!(result["manifest_available"], false);
        assert!(result.get("manifest").is_none());
    }

    #[test]
    fn trusted_key_verifies_signature_and_ciphertext_integrity() {
        let (bytes, signer) = fixture();
        let result = inspect_bytes(&bytes, Some(&signer.public_key())).unwrap();
        assert_eq!(result["signature_verified"], true);
        assert_eq!(result["integrity_verified"], true);
        assert_eq!(result["manifest"]["application_id"], "acme.editor");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (bytes, _) = fixture();
        let stranger = SigningKeyPair::generate().unwrap();
        assert!(inspect_bytes(&bytes, Some(&stranger.public_key())).is_err());
    }

    #[test]
    fn public_key_input_requires_canonical_lowercase_hex() {
        assert!(parse_public_key(&"aB".repeat(32)).is_err());
        assert!(parse_public_key(&"ab".repeat(32)).is_ok());
    }

    #[test]
    fn package_config_builds_a_signed_encrypted_package_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let signer = SigningKeyPair::generate().unwrap();
        let seed = signer.seed();
        std::fs::write(dir.path().join("signing.seed"), seed.as_slice()).unwrap();
        let package_key = SymmetricKey::generate().unwrap();
        std::fs::write(dir.path().join("package.key"), package_key.expose()).unwrap();
        std::fs::write(dir.path().join("module.bin"), b"secret logic").unwrap();
        std::fs::write(
            dir.path().join("build.json"),
            r#"{
                "application_id":"acme.editor",
                "version":"1.2.3",
                "version_counter":7,
                "execution_policy":"software_allowed",
                "created_at":1700000000,
                "signing_seed_file":"signing.seed",
                "package_key_file":"package.key",
                "modules":[{"module_id":"core","abi_version":1,"file":"module.bin"}]
            }"#,
        )
        .unwrap();
        let output = dir.path().join("out.sers");
        let result = build_package_from_config(&dir.path().join("build.json"), &output).unwrap();
        assert_eq!(result["status"], "built");
        assert_eq!(result["signature_verified"], true);
        let bytes = std::fs::read(&output).unwrap();
        let verified = RawPackage::parse(&bytes)
            .unwrap()
            .verify(&signer.public_key())
            .unwrap();
        verified.verify_integrity().unwrap();
        assert_eq!(
            &verified
                .decrypt_module(&package_key, &ModuleId::new("core").unwrap())
                .unwrap()[..],
            b"secret logic"
        );
        assert!(build_package_from_config(&dir.path().join("build.json"), &output).is_err());
    }

    #[test]
    fn package_config_rejects_unknown_fields_and_non_raw_key_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.json"), r#"{"unknown":true}"#).unwrap();
        assert!(
            build_package_from_config(&dir.path().join("bad.json"), &dir.path().join("x")).is_err()
        );

        std::fs::write(dir.path().join("short.key"), [0u8; 31]).unwrap();
        assert!(read_secret_32(&dir.path().join("short.key"), "bad key").is_err());
        std::fs::write(dir.path().join("long.key"), [0u8; 33]).unwrap();
        assert!(read_secret_32(&dir.path().join("long.key"), "bad key").is_err());
    }

    #[test]
    fn identity_outputs_only_public_data_and_valid_registration_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("identity.key"));
        let identity = InstallationIdentity::generate().unwrap();
        let summary = identity_summary(&identity, &store);
        assert_eq!(summary["installation_id"], identity.id().to_string());
        assert_eq!(summary["public_key"], identity.public_key().to_string());
        assert_eq!(summary["key_protection"], "os_file_permissions_only");

        let request = identity.registration_request(&ApplicationId::new("acme.editor").unwrap());
        assert!(request.verify().is_ok());
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["application_id"], "acme.editor");
        assert!(value.get("private_key").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_identity_commands_persist_and_create_registration_request() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("identity.key");
        let initialized = identity_init(&key_path).unwrap();
        let shown = identity_show(&key_path).unwrap();
        assert_eq!(initialized["installation_id"], shown["installation_id"]);
        assert_eq!(shown["key_protection"], "os_file_permissions_only");
        let request = identity_registration_request(&key_path, "acme.editor").unwrap();
        assert_eq!(request["status"], "generated");
        assert_eq!(request["registration_request"]["application_id"], "acme.editor");
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_storage_fails_closed_until_a_platform_store_exists() {
        let dir = tempfile::tempdir().unwrap();
        assert!(identity_init(&dir.path().join("identity.key")).is_err());
        assert!(!dir.path().join("identity.key").exists());
    }
}
