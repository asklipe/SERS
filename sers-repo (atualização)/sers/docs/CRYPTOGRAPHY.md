# Cryptography

All primitives come from RustCrypto / dalek crates behind `crates/sers-crypto`. SERS implements no primitive.
Status: compiled and tested on Windows x64 (see `PROGRESS.md`); not independently audited. Known-answer tests included: SHA-256("abc"), RFC 8032 Ed25519
test 1, RFC 5869 HKDF case 1.

| Purpose | Algorithm | Notes |
|---|---|---|
| Hash | SHA-256 | domain-separated through length-prefixed tags |
| Signatures | Ed25519 | `verify_strict` (canonical signatures, rejects weak keys) |
| Key agreement | X25519 | one-shot ephemeral keys; low-order peer points rejected |
| KDF | HKDF-SHA256 | context in `info`, nonce as salt |
| AEAD | AES-256-GCM | random 96-bit nonce prepended; safe for ~2^32 messages per key, one key per module/session |
| Transport | TLS 1.3 | required by design, not implemented |

Key hierarchy: publisher signing key (kept by the publisher) signs manifests; package key (Key Broker, wrapped
by a KMS/HSM `KeyProvider`) wraps per-module DEKs; installation key (Ed25519, client) proves possession; ephemeral
X25519 keys give per-session key release; the Control Plane authorization key signs grants (`TokenSigner`).

Memory handling: secrets use `Zeroizing` / `ZeroizeOnDrop` and redacted `Debug`. This is best effort. It does
not cover copies in the kernel, swap, crash dumps, registers, or a debugger-privileged attacker, and the
plaintext of a decrypted module is exposed to whoever executes it.

Not implemented: HSM/KMS providers (only `LocalDevKeyProvider`, in-memory, development only), TPM/Secure
Enclave/DPAPI key storage (installation keys sit in a 0600 file on Unix; Windows returns `Unsupported`),
key rotation, post-quantum algorithms.
