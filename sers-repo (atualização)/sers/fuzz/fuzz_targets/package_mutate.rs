#![no_main]
//! A valid package with fuzzer-chosen byte flips. The signature protects the
//! manifest, so this mostly exercises the data section, integrity checks and
//! authenticated decryption; every outcome must be an error or a correct result.

use libfuzzer_sys::fuzz_target;
use sers_core::{ApplicationId, ExecutionPolicy, ModuleId};
use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};
use sers_package::{PackageBuilder, RawPackage};
use std::sync::OnceLock;

struct Fixture {
    package: Vec<u8>,
    signer: SigningKeyPair,
    key: SymmetricKey,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let signer = SigningKeyPair::from_seed(&[1u8; 32]);
        let key = SymmetricKey::from_bytes([2u8; 32]);
        let app = ApplicationId::new("fuzz.app").expect("valid id");
        let mut builder =
            PackageBuilder::new(app, "1.0.0", 1, ExecutionPolicy::SoftwareAllowed, 1)
                .expect("builder");
        builder
            .add_module(ModuleId::new("core").expect("id"), 1, vec![9u8; 300])
            .expect("module");
        let package = builder.build(&signer, &key).expect("package");
        Fixture {
            package,
            signer,
            key,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut bytes = f.package.clone();
    for chunk in data.chunks_exact(3) {
        let index = ((usize::from(chunk[0]) << 8) | usize::from(chunk[1])) % bytes.len();
        bytes[index] ^= chunk[2];
    }
    if let Ok(raw) = RawPackage::parse(&bytes) {
        if let Ok(verified) = raw.verify(&f.signer.public_key()) {
            let _ = verified.verify_integrity();
            let _ = verified.check_package_key(&f.key);
            for entry in &verified.manifest().modules {
                let _ = verified.decrypt_module(&f.key, &entry.module_id);
            }
        }
    }
});
