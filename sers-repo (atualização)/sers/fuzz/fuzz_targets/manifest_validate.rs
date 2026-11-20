#![no_main]
//! Untrusted JSON as a manifest (this is what a verifier would see only after a
//! signature check, but the parser must be robust regardless).

use libfuzzer_sys::fuzz_target;
use sers_package::Manifest;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    if let Ok(manifest) = serde_json::from_slice::<Manifest>(data) {
        let _ = manifest.validate(data.len() as u64);
        let _ = manifest.validate(0);
        let _ = manifest.validate(u64::MAX);
    }
});
