use crate::random::random_array;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sers_core::{PublicKeyBytes, SersError, SignatureBytes};
use zeroize::Zeroizing;

/// Ed25519 key pair. The secret half is zeroized on drop.
pub struct SigningKeyPair {
    inner: SigningKey,
}

impl SigningKeyPair {
    pub fn generate() -> Result<Self, SersError> {
        let seed = Zeroizing::new(random_array::<32>()?);
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte secret seed. Only for persistence by a key store.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes::from_bytes(self.inner.verifying_key().to_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        SignatureBytes::from_bytes(self.inner.sign(message).to_bytes())
    }
}

impl core::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SigningKeyPair(public={}, secret=<redacted>)",
            self.public_key()
        )
    }
}

/// Strict Ed25519 verification (rejects non-canonical signatures and weak keys).
pub fn verify(
    public_key: &PublicKeyBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), SersError> {
    let key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| SersError::InvalidInput("invalid Ed25519 public key"))?;
    let sig = Signature::from_bytes(signature.as_bytes());
    key.verify_strict(message, &sig)
        .map_err(|_| SersError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032, section 7.1, TEST 1 (empty message).
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    fn rfc_pair() -> SigningKeyPair {
        let mut seed = [0u8; 32];
        hex::decode_to_slice(SEED, &mut seed).unwrap();
        SigningKeyPair::from_seed(&seed)
    }

    #[test]
    fn rfc8032_test1_public_key_and_signature() {
        let kp = rfc_pair();
        assert_eq!(kp.public_key().to_string(), PUBLIC);
        assert_eq!(kp.sign(b"").to_string(), SIG);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"message");
        assert!(verify(&kp.public_key(), b"message", &sig).is_ok());
    }

    #[test]
    fn wrong_message_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let sig = kp.sign(b"message");
        assert_eq!(
            verify(&kp.public_key(), b"other", &sig),
            Err(SersError::SignatureInvalid)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = SigningKeyPair::generate().unwrap();
        let b = SigningKeyPair::generate().unwrap();
        let sig = a.sign(b"message");
        assert_eq!(
            verify(&b.public_key(), b"message", &sig),
            Err(SersError::SignatureInvalid)
        );
    }

    #[test]
    fn flipped_signature_bit_is_rejected() {
        let kp = SigningKeyPair::generate().unwrap();
        let mut raw = *kp.sign(b"message").as_bytes();
        raw[10] ^= 0x01;
        let bad = SignatureBytes::from_bytes(raw);
        assert!(verify(&kp.public_key(), b"message", &bad).is_err());
    }

    #[test]
    fn debug_hides_secret() {
        let kp = rfc_pair();
        let s = format!("{kp:?}");
        assert!(!s.contains(SEED));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn seed_roundtrip() {
        let kp = SigningKeyPair::generate().unwrap();
        let again = SigningKeyPair::from_seed(&kp.seed());
        assert_eq!(kp.public_key(), again.public_key());
    }
}
