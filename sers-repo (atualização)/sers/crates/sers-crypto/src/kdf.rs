use crate::secret::SymmetricKey;
use hkdf::Hkdf;
use sers_core::SersError;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF-SHA256 (RFC 5869). An empty `salt` means "no salt".
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), SersError> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .map_err(|_| SersError::Crypto("HKDF output length invalid"))
}

/// Derives a 256-bit key. `info` must identify the purpose (domain separation).
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SymmetricKey, SersError> {
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf_sha256(ikm, salt, info, &mut *okm)?;
    Ok(SymmetricKey::from_bytes(*okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869, Appendix A.1 (SHA-256).
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn different_info_gives_different_keys() {
        let a = derive_key(b"ikm", b"salt", b"purpose-a").unwrap();
        let b = derive_key(b"ikm", b"salt", b"purpose-b").unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn oversized_output_is_an_error() {
        let mut out = vec![0u8; 255 * 32 + 1];
        assert!(hkdf_sha256(b"ikm", b"", b"", &mut out).is_err());
    }
}
