use sers_core::{PublicKeyBytes, SersError, SignatureBytes};
use sers_crypto::{aead, secret::SymmetricKey, sign::SigningKeyPair};
use zeroize::Zeroizing;

/// Master-key abstraction for the Key Broker (envelope encryption).
///
/// Production implementations must delegate to an HSM or cloud KMS (AWS KMS,
/// GCP KMS, Azure Key Vault, PKCS#11, HashiCorp Vault transit) so that the
/// master key never enters this process. None is implemented yet.
pub trait KeyProvider: Send + Sync {
    /// Seals `key`, binding it to `context` (authenticated, not secret).
    fn wrap(&self, context: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, SersError>;
    fn unwrap(&self, context: &[u8], wrapped: &[u8]) -> Result<SymmetricKey, SersError>;
}

/// **Development only.** The master key lives in process memory and is lost on
/// exit. Never use it to protect real packages.
pub struct LocalDevKeyProvider {
    master: SymmetricKey,
}

impl LocalDevKeyProvider {
    pub fn generate() -> Result<Self, SersError> {
        Ok(Self {
            master: SymmetricKey::generate()?,
        })
    }
}

impl KeyProvider for LocalDevKeyProvider {
    fn wrap(&self, context: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, SersError> {
        aead::seal(&self.master, context, key.expose())
    }

    fn unwrap(&self, context: &[u8], wrapped: &[u8]) -> Result<SymmetricKey, SersError> {
        let plain = aead::open(&self.master, context, wrapped)?;
        if plain.len() != SymmetricKey::LEN {
            return Err(SersError::Crypto("unwrapped key has wrong length"));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&plain);
        Ok(SymmetricKey::from_bytes(*bytes))
    }
}

/// Signs authorization tokens. Production: an HSM/KMS-backed signer.
pub trait TokenSigner: Send + Sync {
    fn public_key(&self) -> PublicKeyBytes;
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes, SersError>;
}

/// Dev signer (key in memory).
impl TokenSigner for SigningKeyPair {
    fn public_key(&self) -> PublicKeyBytes {
        SigningKeyPair::public_key(self)
    }

    fn sign(&self, message: &[u8]) -> Result<SignatureBytes, SersError> {
        Ok(SigningKeyPair::sign(self, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let p = LocalDevKeyProvider::generate().unwrap();
        let key = SymmetricKey::generate().unwrap();
        let wrapped = p.wrap(b"ctx", &key).unwrap();
        assert_eq!(p.unwrap(b"ctx", &wrapped).unwrap().expose(), key.expose());
    }

    #[test]
    fn wrong_context_or_tampering_fails() {
        let p = LocalDevKeyProvider::generate().unwrap();
        let key = SymmetricKey::generate().unwrap();
        let mut wrapped = p.wrap(b"ctx", &key).unwrap();
        assert!(p.unwrap(b"other", &wrapped).is_err());
        wrapped[20] ^= 1;
        assert!(p.unwrap(b"ctx", &wrapped).is_err());
        assert!(p.unwrap(b"ctx", &[]).is_err());
    }

    #[test]
    fn another_master_key_cannot_unwrap() {
        let a = LocalDevKeyProvider::generate().unwrap();
        let b = LocalDevKeyProvider::generate().unwrap();
        let wrapped = a.wrap(b"ctx", &SymmetricKey::generate().unwrap()).unwrap();
        assert!(b.unwrap(b"ctx", &wrapped).is_err());
    }
}
