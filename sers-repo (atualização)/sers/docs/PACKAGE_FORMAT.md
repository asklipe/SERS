# `.sers` package format, version 1

Implementation: `crates/sers-package` (compiled and tested on Windows x64; see `PROGRESS.md`). Rationale: ADR 0001.

```text
offset  size  field
0       8     magic = "SERSPKG" 0x01
8       32    publisher_key_id  = SHA-256("SERS-PUBLISHER-KEY-ID-v1\0" || ed25519 public key)
40      4     manifest_len      (u32, big endian, 1..=1 MiB)
44      64    signature         Ed25519 over the signing input below
108     n     manifest          JSON, exactly the signed bytes
108+n   ...   module data       concatenated ciphertexts, tiled exactly by the manifest
```

Signing input: `"SERS-PACKAGE-SIGNATURE-v1\0" || publisher_key_id || u32be(manifest_len) || manifest`.
The package digest used towards the Control Plane is
`SHA-256("SERS-MANIFEST-DIGEST-v1\0" || manifest)`; the manifest commits to every module hash.

## Manifest

`format_version` (1), `package_id` (16 random bytes), `application_id`, `publisher_key_id`,
`version` (`[0-9A-Za-z.+-]`, 1..=64), `version_counter` (monotonic, anti-downgrade),
`created_at`, `execution_policy` (`software_allowed` | `hardware_required` |
`remote_execution_required`), and `modules[]`:
`module_id`, `abi_version`, `offset`, `ciphertext_len`, `plaintext_len`,
`ciphertext_sha256`, `wrapped_dek`. Unknown fields are rejected.

## Encryption (envelope)

* Each module has a fresh random 256-bit key (DEK). Module ciphertext: AES-256-GCM,
  random 96-bit nonce prepended, AAD = `"SERS-MODULE-v1\0" || package_id || len+application_id || len+module_id || u64be(plaintext_len) || u32be(abi_version)`.
* DEKs are wrapped (AES-256-GCM) under the **package key** with
  AAD = `"SERS-DEK-WRAP-v1\0" || package_id || len+application_id || len+module_id`.
* The package key is registered with the Control Plane Key Broker (wrapped by a
  KMS/HSM `KeyProvider`) and is released only after a successful authorization.

## Verification order (reader)

1. Structural parse: magic, lengths, size limits (1 GiB package, 1 MiB manifest). No allocation from attacker-chosen sizes.
2. Look up the publisher key by `publisher_key_id` in a **trusted** set; refuse unknown publishers.
3. Verify the signature, **then** parse the manifest.
4. Validate: version, module count (<= 256), unique ids, `ciphertext_len = plaintext_len + 28`,
   `plaintext_len <= 256 MiB`, offsets contiguous from 0, total equals the real data length
   (no gaps, overlaps or trailing bytes), manifest publisher id equals the header's.
5. Module hashes (`verify_integrity`) and authenticated decryption (`decrypt_module`).

Downgrade protection: `version_counter` compared with a floor kept by the Loader
and the Control Plane (the floor only rises). Revocation: `package_id` lists.

## Not covered yet

Signature timestamps / transparency log (Sigstore, TUF) for publisher keys and
package provenance (in-toto, SLSA) are not implemented. Key rotation of the
package key requires re-building and re-signing the package. The module ABI
(`abi_version`) is a number only; no ABI is specified or implemented yet.
