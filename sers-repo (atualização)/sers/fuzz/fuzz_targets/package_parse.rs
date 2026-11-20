#![no_main]
//! Arbitrary bytes as a `.sers` file: structural parsing and signature
//! verification must never panic.

use libfuzzer_sys::fuzz_target;
use sers_core::PublicKeyBytes;
use sers_package::RawPackage;

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = RawPackage::parse(data) {
        let _ = raw.manifest_digest();
        let _ = raw.publisher_key_id();
        let key = PublicKeyBytes::from_bytes([7u8; 32]);
        let _ = raw.verify(&key);
    }
});
