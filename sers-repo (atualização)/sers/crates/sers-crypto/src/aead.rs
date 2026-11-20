//! AES-256-GCM with a random 96-bit nonce.
//!
//! Sealed layout: `nonce (12) || ciphertext || tag (16)`.
//!
//! Random nonces are safe for up to ~2^32 messages per key. SERS uses one key
//! per module / session, so this bound is not approached; do not reuse a key
//! for unbounded message streams.

#![allow(deprecated)] // generic-array 0.14 `from_slice`, still required by aes-gcm 0.10

use crate::{random::random_array, secret::SymmetricKey};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sers_core::SersError;
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

fn cipher(key: &SymmetricKey) -> Result<Aes256Gcm, SersError> {
    Aes256Gcm::new_from_slice(key.expose()).map_err(|_| SersError::Crypto("invalid AES-256 key"))
}

/// Encrypts `plaintext`, authenticating `aad` (never encrypted, but bound).
pub fn seal(key: &SymmetricKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SersError> {
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = cipher(key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SersError::Crypto("AEAD encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts and authenticates. The plaintext is zeroized on drop.
pub fn open(
    key: &SymmetricKey,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SersError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(SersError::InvalidInput("sealed data too short"));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let plaintext = cipher(key)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SersError::Crypto("AEAD authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let sealed = seal(&key, b"aad", b"hello").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 5 + TAG_LEN);
        let pt = open(&key, b"aad", &sealed).unwrap();
        assert_eq!(&pt[..], &b"hello"[..]);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let sealed = seal(&key, b"", b"").unwrap();
        assert!(open(&key, b"", &sealed).unwrap().is_empty());
    }

    #[test]
    fn nonces_are_fresh() {
        let key = SymmetricKey::generate().unwrap();
        let a = seal(&key, b"", b"x").unwrap();
        let b = seal(&key, b"", b"x").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let mut sealed = seal(&key, b"aad", b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&key, b"aad", &sealed).is_err());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let mut sealed = seal(&key, b"aad", b"hello").unwrap();
        sealed[0] ^= 0x01;
        assert!(open(&key, b"aad", &sealed).is_err());
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        let sealed = seal(&key, b"module-1", b"hello").unwrap();
        assert!(open(&key, b"module-2", &sealed).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let k1 = SymmetricKey::generate().unwrap();
        let k2 = SymmetricKey::generate().unwrap();
        let sealed = seal(&k1, b"", b"hello").unwrap();
        assert!(open(&k2, b"", &sealed).is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        let key = SymmetricKey::generate().unwrap();
        assert!(open(&key, b"", &[0u8; NONCE_LEN + TAG_LEN - 1]).is_err());
        assert!(open(&key, b"", &[]).is_err());
    }
}
