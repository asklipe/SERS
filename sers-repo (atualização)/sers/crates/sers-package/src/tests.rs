use crate::builder::assemble;
use crate::format::{HEADER_LEN, MAGIC, MAX_MODULE_PLAINTEXT_BYTES};
use crate::*;
use sers_core::{ApplicationId, ExecutionPolicy, ModuleId, PublisherKeyId, SersError};
use sers_crypto::{secret::SymmetricKey, sign::SigningKeyPair};

const NOW: u64 = 1_700_000_000;

fn boxed(f: impl Fn(&mut Manifest) + 'static) -> Box<dyn Fn(&mut Manifest)> {
    Box::new(f)
}

fn app() -> ApplicationId {
    ApplicationId::new("acme.editor").unwrap()
}

fn mid(s: &str) -> ModuleId {
    ModuleId::new(s).unwrap()
}

fn builder(counter: u64) -> PackageBuilder {
    PackageBuilder::new(
        app(),
        "1.0.0",
        counter,
        ExecutionPolicy::SoftwareAllowed,
        NOW,
    )
    .unwrap()
}

fn sample(signer: &SigningKeyPair, key: &SymmetricKey) -> Vec<u8> {
    let mut b = builder(1);
    b.add_module(mid("core"), 1, b"alpha secret logic".to_vec())
        .unwrap();
    b.add_module(mid("ui-logic"), 1, vec![7u8; 5000]).unwrap();
    b.build(signer, key).unwrap()
}

/// Returns the verified manifest and a copy of the data section.
fn split(bytes: &[u8], signer: &SigningKeyPair) -> (Manifest, Vec<u8>) {
    let v = RawPackage::parse(bytes)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    let manifest = v.manifest().clone();
    let manifest_len: usize =
        u32::from_be_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as usize;
    (manifest, bytes[HEADER_LEN + manifest_len..].to_vec())
}

fn verify_err(bytes: &[u8], signer: &SigningKeyPair) -> SersError {
    RawPackage::parse(bytes)
        .and_then(|r| r.verify(&signer.public_key()))
        .unwrap_err()
}

#[test]
fn roundtrip_two_modules() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    let v = RawPackage::parse(&bytes)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    v.verify_integrity().unwrap();
    v.check_package_key(&key).unwrap();
    assert_eq!(
        &v.decrypt_module(&key, &mid("core")).unwrap()[..],
        &b"alpha secret logic"[..]
    );
    assert_eq!(
        &v.decrypt_module(&key, &mid("ui-logic")).unwrap()[..],
        &vec![7u8; 5000][..]
    );
    assert!(v.decrypt_module(&key, &mid("missing")).is_err());
    assert_eq!(v.manifest().application_id, app());
    assert_eq!(v.manifest().version_counter, 1);
}

#[test]
fn plaintext_does_not_appear_in_the_package() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    let needle = b"alpha secret logic";
    assert!(!bytes.windows(needle.len()).any(|w| w == needle));
}

#[test]
fn wrong_publisher_key_is_rejected() {
    let signer = SigningKeyPair::generate().unwrap();
    let other = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    assert!(matches!(
        verify_err(&bytes, &other),
        SersError::PolicyDenied(_)
    ));
}

#[test]
fn tampered_manifest_is_rejected_before_parsing() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let mut bytes = sample(&signer, &key);
    bytes[HEADER_LEN + 10] ^= 0x01;
    assert_eq!(verify_err(&bytes, &signer), SersError::SignatureInvalid);
}

#[test]
fn tampered_signature_is_rejected() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let mut bytes = sample(&signer, &key);
    bytes[50] ^= 0x01;
    assert_eq!(verify_err(&bytes, &signer), SersError::SignatureInvalid);
}

#[test]
fn tampered_data_is_caught_by_integrity_and_decryption() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let mut bytes = sample(&signer, &key);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let v = RawPackage::parse(&bytes)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    assert!(v.verify_integrity().is_err());
    assert!(v.decrypt_module(&key, &mid("ui-logic")).is_err());
}

#[test]
fn truncated_and_extended_packages_are_rejected() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    for cut in [0usize, 1, 8, 40, HEADER_LEN - 1, HEADER_LEN, HEADER_LEN + 5] {
        assert!(RawPackage::parse(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    assert!(matches!(
        verify_err(&bytes[..bytes.len() - 1], &signer),
        SersError::InvalidInput(_)
    ));
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(
        verify_err(&longer, &signer),
        SersError::InvalidInput(_)
    ));
}

#[test]
fn bad_magic_and_oversized_manifest_length_are_rejected() {
    let mut bytes = vec![0u8; HEADER_LEN + 4];
    assert!(RawPackage::parse(&bytes).is_err());
    bytes[..8].copy_from_slice(MAGIC);
    bytes[40..44].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(RawPackage::parse(&bytes).is_err());
    bytes[40..44].copy_from_slice(&0u32.to_be_bytes());
    assert!(RawPackage::parse(&bytes).is_err());
}

#[test]
fn wrong_package_key_cannot_decrypt() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let wrong = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    let v = RawPackage::parse(&bytes)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    assert!(v.check_package_key(&wrong).is_err());
    assert!(v.decrypt_module(&wrong, &mid("core")).is_err());
}

#[test]
fn forged_but_signed_manifests_fail_validation() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    let (good, data) = split(&bytes, &signer);

    type ManifestMutation = Box<dyn Fn(&mut Manifest)>;
    let mutations: Vec<(&str, ManifestMutation)> = vec![
        (
            "duplicate id",
            boxed(|m| m.modules[1].module_id = m.modules[0].module_id.clone()),
        ),
        ("gap", boxed(|m| m.modules[1].offset += 1)),
        ("overlap", boxed(|m| m.modules[1].offset -= 1)),
        (
            "ciphertext length",
            boxed(|m| m.modules[0].ciphertext_len += 1),
        ),
        ("format version", boxed(|m| m.format_version = 2)),
        ("abi zero", boxed(|m| m.modules[0].abi_version = 0)),
        ("bad version string", boxed(|m| m.version = "1 0".into())),
        ("no modules", boxed(|m| m.modules.clear())),
        (
            "oversized module",
            boxed(|m| {
                m.modules[0].plaintext_len = MAX_MODULE_PLAINTEXT_BYTES + 1;
                m.modules[0].ciphertext_len = MAX_MODULE_PLAINTEXT_BYTES + 1 + 28;
            }),
        ),
        (
            "publisher id mismatch",
            boxed(|m| m.publisher_key_id = PublisherKeyId::from_bytes([9; 32])),
        ),
    ];
    for (name, mutate) in mutations {
        let mut m = good.clone();
        mutate(&mut m);
        let forged = assemble(&signer, &m, &data).unwrap();
        let r = RawPackage::parse(&forged).and_then(|r| r.verify(&signer.public_key()));
        assert!(r.is_err(), "mutation accepted: {name}");
    }
}

#[test]
fn swapping_module_ids_breaks_authenticated_decryption() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let bytes = sample(&signer, &key);
    let (mut m, data) = split(&bytes, &signer);
    let (a, b) = (
        m.modules[0].module_id.clone(),
        m.modules[1].module_id.clone(),
    );
    m.modules[0].module_id = b;
    m.modules[1].module_id = a;
    let forged = assemble(&signer, &m, &data).unwrap();
    let v = RawPackage::parse(&forged)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    assert!(v.decrypt_module(&key, &mid("core")).is_err());
    assert!(v.decrypt_module(&key, &mid("ui-logic")).is_err());
    assert!(v.check_package_key(&key).is_err());
}

#[test]
fn manifest_digest_is_stable_and_package_specific() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let a = sample(&signer, &key);
    let b = sample(&signer, &key);
    let raw_a = RawPackage::parse(&a).unwrap();
    let digest_a = raw_a.manifest_digest();
    let verified = raw_a.verify(&signer.public_key()).unwrap();
    assert_eq!(verified.manifest_digest(), digest_a);
    assert_ne!(RawPackage::parse(&b).unwrap().manifest_digest(), digest_a);
}

#[test]
fn builder_rejects_invalid_input() {
    assert!(PackageBuilder::new(
        app(),
        "bad version!",
        1,
        ExecutionPolicy::SoftwareAllowed,
        NOW
    )
    .is_err());
    let mut b = builder(1);
    assert!(b.add_module(mid("core"), 0, vec![1]).is_err());
    b.add_module(mid("core"), 1, vec![1]).unwrap();
    assert!(b.add_module(mid("core"), 1, vec![2]).is_err());
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    assert!(builder(1).build(&signer, &key).is_err());
}

#[test]
fn parser_never_panics_on_garbage() {
    for len in 0..300usize {
        let v = vec![0xABu8; len];
        let _ = RawPackage::parse(&v);
        let mut with_magic = MAGIC.to_vec();
        with_magic.extend(vec![0x41u8; len]);
        let _ = RawPackage::parse(&with_magic);
    }
}

#[test]
fn execution_policy_is_part_of_the_signed_manifest() {
    let signer = SigningKeyPair::generate().unwrap();
    let key = SymmetricKey::generate().unwrap();
    let mut b =
        PackageBuilder::new(app(), "2.0.0", 2, ExecutionPolicy::HardwareRequired, NOW).unwrap();
    b.add_module(mid("core"), 1, vec![1, 2, 3]).unwrap();
    let bytes = b.build(&signer, &key).unwrap();
    let v = RawPackage::parse(&bytes)
        .unwrap()
        .verify(&signer.public_key())
        .unwrap();
    assert_eq!(
        v.manifest().execution_policy,
        ExecutionPolicy::HardwareRequired
    );
}
