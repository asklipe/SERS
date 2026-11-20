//! Validated identifiers and fixed-size byte newtypes.
//!
//! Byte newtypes serialize as **lowercase hex** and reject anything else
//! (uppercase, wrong length, non-hex), so every value has one canonical form.

use crate::SersError;
use serde::{Deserialize, Serialize};

macro_rules! hex_newtype {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl core::str::FromStr for $name {
            type Err = SersError;

            fn from_str(s: &str) -> Result<Self, SersError> {
                if s.len() != $len * 2
                    || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err(SersError::InvalidInput(concat!(
                        stringify!($name),
                        ": expected lowercase hex of exact length"
                    )));
                }
                let mut out = [0u8; $len];
                hex::decode_to_slice(s, &mut out)
                    .map_err(|_| SersError::InvalidInput(concat!(stringify!($name), ": invalid hex")))?;
                Ok(Self(out))
            }
        }

        impl TryFrom<String> for $name {
            type Error = SersError;

            fn try_from(value: String) -> Result<Self, SersError> {
                value.parse::<$name>()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                hex::encode(value.0)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }
    };
}

hex_newtype!(
    /// Installation identifier: SHA-256 over a domain-separated public key.
    /// An identifier, **not** a secret.
    InstallationId,
    32
);
hex_newtype!(
    /// SHA-256 digest (package manifest hash, module hash, ...).
    Digest32,
    32
);
hex_newtype!(
    /// 256-bit random challenge nonce.
    Nonce32,
    32
);
hex_newtype!(
    /// Ed25519 public key (compressed point, 32 bytes).
    PublicKeyBytes,
    32
);
hex_newtype!(
    /// Ed25519 signature (64 bytes).
    SignatureBytes,
    64
);

hex_newtype!(
    /// Random per-package identifier.
    PackageId,
    16
);
hex_newtype!(
    /// SHA-256 over a domain-separated publisher public key.
    PublisherKeyId,
    32
);
hex_newtype!(
    /// Activation credential of a license: 128 random bits, so treat it as a secret.
    LicenseId,
    16
);
hex_newtype!(
    /// X25519 public key (ephemeral, used for key release).
    X25519PublicKey,
    32
);
hex_newtype!(
    /// AES-256-GCM sealed 32-byte key: nonce (12) || ciphertext (32) || tag (16).
    WrappedKey,
    60
);

fn is_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// Rules: `min..=max` bytes of `[a-z0-9._-]`, starts and ends with `[a-z0-9]`,
/// no two consecutive separators.
fn validate_slug(value: &str, min: usize, max: usize) -> Result<(), SersError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() < min || bytes.len() > max {
        return Err(SersError::InvalidInput("identifier length out of range"));
    }
    if !bytes
        .iter()
        .all(|&b| is_alnum(b) || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(SersError::InvalidInput(
            "identifier contains forbidden characters",
        ));
    }
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(SersError::InvalidInput(
            "identifier must start and end with [a-z0-9]",
        ));
    }
    if bytes
        .windows(2)
        .any(|w| !is_alnum(w[0]) && !is_alnum(w[1]))
    {
        return Err(SersError::InvalidInput(
            "identifier has consecutive separators",
        ));
    }
    Ok(())
}

macro_rules! slug_newtype {
    ($(#[$meta:meta])* $name:ident, $min:expr, $max:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub const MIN_LEN: usize = $min;
            pub const MAX_LEN: usize = $max;

            pub fn new(value: impl Into<String>) -> Result<Self, SersError> {
                let value = value.into();
                validate_slug(&value, Self::MIN_LEN, Self::MAX_LEN)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = SersError;

            fn try_from(value: String) -> Result<Self, SersError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

slug_newtype!(
    /// Reverse-DNS style application identifier, e.g. `acme.editor` (3..=128).
    ApplicationId,
    3,
    128
);
slug_newtype!(
    /// Module identifier inside a package, e.g. `core` (1..=64).
    ModuleId,
    1,
    64
);
slug_newtype!(
    /// Tenant (company) identifier (3..=64).
    TenantId,
    3,
    64
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_serde_roundtrip_is_lowercase_hex() {
        let d = Digest32::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let back: Digest32 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn hex_newtypes_reject_non_canonical_input() {
        assert!("AB".repeat(32).parse::<Digest32>().is_err(), "uppercase");
        assert!("ab".repeat(31).parse::<Digest32>().is_err(), "too short");
        assert!("ab".repeat(33).parse::<Digest32>().is_err(), "too long");
        assert!("zz".repeat(32).parse::<Digest32>().is_err(), "not hex");
        assert!("ab".repeat(32).parse::<SignatureBytes>().is_err(), "wrong size");
        assert!("ab".repeat(64).parse::<SignatureBytes>().is_ok());
    }

    #[test]
    fn application_id_accepts_valid_values() {
        for ok in ["acme.editor", "a-b", "company.product_2", "abc", "x1.y2.z3"] {
            assert!(ApplicationId::new(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn application_id_rejects_invalid_values() {
        let too_long = "a".repeat(129);
        for bad in [
            "",
            "ab",
            "Acme.editor",
            "acme editor",
            "acme/../x",
            ".acme",
            "acme.",
            "acme..editor",
            "acme.-editor",
            "acme\0x",
            "acmé.editor",
            too_long.as_str(),
        ] {
            assert!(ApplicationId::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn application_id_is_validated_on_deserialize() {
        assert!(serde_json::from_str::<ApplicationId>("\"acme.editor\"").is_ok());
        assert!(serde_json::from_str::<ApplicationId>("\"../etc\"").is_err());
    }
}

#[cfg(test)]
mod slug_tests {
    use super::*;

    #[test]
    fn module_and_tenant_ids_follow_the_same_rules() {
        assert!(ModuleId::new("core").is_ok());
        assert!(ModuleId::new("m").is_ok());
        assert!(ModuleId::new("module_001").is_ok());
        assert!(ModuleId::new("../core").is_err());
        assert!(ModuleId::new("Core").is_err());
        assert!(ModuleId::new("a".repeat(65)).is_err());
        assert!(TenantId::new("acme").is_ok());
        assert!(TenantId::new("ac").is_err());
        assert!(TenantId::new("acme corp").is_err());
    }

    #[test]
    fn new_hex_types_have_expected_sizes() {
        assert!("ab".repeat(16).parse::<PackageId>().is_ok());
        assert!("ab".repeat(16).parse::<LicenseId>().is_ok());
        assert!("ab".repeat(32).parse::<PublisherKeyId>().is_ok());
        assert!("ab".repeat(32).parse::<X25519PublicKey>().is_ok());
        assert!("ab".repeat(60).parse::<WrappedKey>().is_ok());
        assert!("ab".repeat(59).parse::<WrappedKey>().is_err());
    }
}
