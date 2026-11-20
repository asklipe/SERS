use rand_core::OsRng;
use sers_core::SersError;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

/// Single-use X25519 key pair: `agree` consumes it, so the secret cannot be reused.
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Raw DH output. Do **not** use it as a key directly: pass it through
    /// `kdf::derive_key` with a context-specific `info`.
    pub fn agree(self, peer_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, SersError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(SersError::Crypto("X25519 peer key is a low-order point"));
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_secret() {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let (pa, pb) = (a.public_key(), b.public_key());
        let sa = a.agree(&pb).unwrap();
        let sb = b.agree(&pa).unwrap();
        assert_eq!(*sa, *sb);
    }

    #[test]
    fn low_order_peer_key_is_rejected() {
        let a = EphemeralKeyPair::generate();
        assert!(a.agree(&[0u8; 32]).is_err());
    }
}
