#![no_main]
//! Identifier and byte-newtype parsing from arbitrary text.

use libfuzzer_sys::fuzz_target;
use sers_core::{
    ApplicationId, Digest32, InstallationId, ModuleId, Nonce32, PublicKeyBytes, SignatureBytes,
    TenantId, WrappedKey,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = text.parse::<Digest32>();
    let _ = text.parse::<InstallationId>();
    let _ = text.parse::<Nonce32>();
    let _ = text.parse::<PublicKeyBytes>();
    let _ = text.parse::<SignatureBytes>();
    let _ = text.parse::<WrappedKey>();
    let _ = ApplicationId::new(text);
    let _ = ModuleId::new(text);
    let _ = TenantId::new(text);
});
