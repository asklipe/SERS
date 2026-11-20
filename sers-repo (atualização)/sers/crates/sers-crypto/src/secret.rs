use crate::random::random_array;
use sers_core::SersError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 256-bit symmetric key, zeroized on drop, redacted in `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub const LEN: usize = 32;

    pub fn generate() -> Result<Self, SersError> {
        Ok(Self(random_array::<32>()?))
    }

    /// Takes ownership of a copy of `bytes`; the caller should zeroize its own copy.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_key() {
        let k = SymmetricKey::from_bytes([0x41; 32]);
        let s = format!("{k:?}");
        assert!(!s.contains("41"));
        assert!(s.contains("redacted"));
    }
}
