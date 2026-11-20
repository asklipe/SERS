//! Persistence of the installation key.
//!
//! `FileKeyStore` keeps the 32-byte Ed25519 seed in a file readable only by
//! the current user (mode 0600, symlinks and loose permissions rejected).
//! This protects against other *unprivileged* local users. It does **not**
//! protect against malware running as the same user or against root, and it
//! is not hardware-backed. Platform stores (TPM / Secure Enclave / DPAPI)
//! are not implemented.

use crate::identity::InstallationIdentity;
use sers_core::SersError;
use std::path::{Path, PathBuf};

/// How strongly the private key is protected at rest. Reported honestly so
/// policies can refuse weak stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// Plain file protected by OS file permissions only.
    OsFilePermissionsOnly,
}

pub trait KeyStore {
    fn protection(&self) -> KeyProtection;
    /// `Ok(None)` when no key has been stored yet.
    fn load(&self) -> Result<Option<InstallationIdentity>, SersError>;
    /// Stores a new identity; fails if one already exists (never overwrites).
    fn create(&self, identity: &InstallationIdentity) -> Result<(), SersError>;
}

/// Loads the stored identity or generates and stores a new one.
pub fn load_or_create(store: &dyn KeyStore) -> Result<InstallationIdentity, SersError> {
    if let Some(identity) = store.load()? {
        return Ok(identity);
    }
    let identity = InstallationIdentity::generate()?;
    store.create(&identity)?;
    Ok(identity)
}

const MAGIC: &[u8; 8] = b"SERSKEY1";
const FILE_LEN: usize = 8 + 32;

pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl KeyStore for FileKeyStore {
    fn protection(&self) -> KeyProtection {
        KeyProtection::OsFilePermissionsOnly
    }

    fn load(&self) -> Result<Option<InstallationIdentity>, SersError> {
        use std::io::ErrorKind;
        use std::os::unix::fs::PermissionsExt;
        use zeroize::Zeroizing;

        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !meta.file_type().is_file() {
            return Err(SersError::Io("key path is not a regular file".into()));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(SersError::PolicyDenied(
                "key file permissions are too permissive",
            ));
        }
        let data = Zeroizing::new(std::fs::read(&self.path)?);
        if data.len() != FILE_LEN || data[..8] != MAGIC[..] {
            return Err(SersError::InvalidInput(
                "key file is corrupted or has an unsupported format",
            ));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&data[8..]);
        Ok(Some(InstallationIdentity::from_seed(&seed)))
    }

    fn create(&self, identity: &InstallationIdentity) -> Result<(), SersError> {
        use std::fs::OpenOptions;
        use std::io::{ErrorKind, Write};
        use std::os::unix::fs::OpenOptionsExt;
        use zeroize::Zeroizing;

        let mut data = Zeroizing::new(Vec::with_capacity(FILE_LEN));
        data.extend_from_slice(MAGIC);
        let seed = identity.seed();
        data.extend_from_slice(&seed[..]);

        // Write a private temp file, then hard-link it to the final name:
        // the link fails if the destination exists, so a key is never
        // overwritten, and readers never observe a half-written file.
        let tmp = self.path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = file.write_all(&data).and_then(|_| file.sync_all());
        drop(file);
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        let linked = std::fs::hard_link(&tmp, &self.path);
        let _ = std::fs::remove_file(&tmp);
        linked.map_err(|e| {
            if e.kind() == ErrorKind::AlreadyExists {
                SersError::Io("key file already exists".into())
            } else {
                e.into()
            }
        })
    }
}

#[cfg(not(unix))]
impl KeyStore for FileKeyStore {
    fn protection(&self) -> KeyProtection {
        KeyProtection::OsFilePermissionsOnly
    }

    fn load(&self) -> Result<Option<InstallationIdentity>, SersError> {
        Err(SersError::Unsupported(
            "secure key file storage is only implemented for Unix; a platform key store is required",
        ))
    }

    fn create(&self, _identity: &InstallationIdentity) -> Result<(), SersError> {
        Err(SersError::Unsupported(
            "secure key file storage is only implemented for Unix; a platform key store is required",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store_in(dir: &tempfile::TempDir) -> FileKeyStore {
        FileKeyStore::new(dir.path().join("installation.key"))
    }

    #[test]
    fn load_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store_in(&dir).load().unwrap().is_none());
    }

    #[test]
    fn create_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let identity = InstallationIdentity::generate().unwrap();
        store.create(&identity).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.id(), identity.id());
        assert_eq!(loaded.public_key(), identity.public_key());
    }

    #[test]
    fn key_file_is_owner_only_and_temp_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.create(&InstallationIdentity::generate().unwrap()).unwrap();
        let mode = std::fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!store.path().with_extension("tmp").exists());
    }

    #[test]
    fn create_never_overwrites_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let first = InstallationIdentity::generate().unwrap();
        store.create(&first).unwrap();
        assert!(store.create(&InstallationIdentity::generate().unwrap()).is_err());
        assert_eq!(store.load().unwrap().unwrap().id(), first.id());
    }

    #[test]
    fn permissive_mode_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        store.create(&InstallationIdentity::generate().unwrap()).unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(store.load(), Err(SersError::PolicyDenied(_))));
    }

    #[test]
    fn corrupted_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        std::fs::write(store.path(), b"not a key").unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(store.load(), Err(SersError::InvalidInput(_))));
    }

    #[test]
    fn symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.key");
        std::fs::write(&real, [0u8; FILE_LEN]).unwrap();
        let link = dir.path().join("installation.key");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(FileKeyStore::new(link).load().is_err());
    }

    #[test]
    fn load_or_create_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let a = load_or_create(&store).unwrap();
        let b = load_or_create(&store).unwrap();
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn protection_level_is_reported_honestly() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            store_in(&dir).protection(),
            KeyProtection::OsFilePermissionsOnly
        );
    }
}
