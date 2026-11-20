# SERS progress

## Snapshot

This status describes the source snapshot provided as `sers-repo.zip` on 2026-11-20. The archive contains the Rust workspace and documentation, but no `.git` directory, `Cargo.lock`, `LICENSE`, or `AGENTS.md`. Instructions supplied with the request were used as project guidance; archive documents were treated as technical requirements and status evidence, not as separate user requests.

A user-authorized Rust stable x64 toolchain was installed in the user profile. The official rustup installer checksum was verified before execution. `Cargo.lock` is generated and included in the project workspace now.

## Verified on Windows x64 (2026-11-20)

- `cargo check --workspace`: passed.
- `cargo build --workspace --all-targets`: passed.
- `cargo test --workspace`: passed, 148 tests, 0 failures on Windows x64.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo run -p sers-controlplane --example protected_flow`: passed; it encrypted a package, completed authorization, released the session-sealed key, denied a revoked installation, denied `hardware_required`, and verified a 13-event audit chain.
- `cargo audit`: passed with exit code 0; no advisories found in the lockfile at scan time.
- `cargo deny check`: passed; advisories, bans, licenses, and sources passed. One non-failing duplicate-version warning remains for `syn` 2.x/3.x.
- CLI implemented: `sers backend detect` emits the platform/backend report as JSON; `sers inspect` only exposes header metadata before trust, and with a supplied public key verifies the signature and ciphertext integrity before displaying the manifest; `sers package build` builds from a strict JSON config, bounded binary key/module files, verifies the result, and refuses to overwrite; `sers identity` initializes, shows and creates local proof-of-possession requests where the file keystore is supported. Eight CLI tests and one unsupported-keystore test pass on Windows (the Unix persistence test runs only on Linux). Raw publisher/package key files are externally provisioned and must be protected by the caller.
- Migration hardened with composite tenant/application/package foreign keys, a wrapped-key length check, broader row-level policies, and narrow `SECURITY DEFINER` tenant-resolution functions for auth/protocol roles. The CI smoke test checks RLS behavior and cross-tenant package references. The SQL is still pending its first PostgreSQL execution in CI. RLS context is defense in depth only because the service SQL role can change its custom tenant setting.

Initial Clippy findings were fixed: redundant RNG borrowing, unnecessary workspace dependency aliases, test type complexity, test allocation idiom, oversized authorization enum variant, and Windows dead-code warnings for Unix-only key-store symbols. The authorization grant variant now boxes its grant.

## Remaining verification

- Linux CI and Unix-only `FileKeyStore` tests have not run.
- PostgreSQL migration is unverified locally; neither `psql`/`postgres` nor Docker/Podman is available. A disposable PostgreSQL CI job applies the schema and tests tenant RLS plus the narrow API-key lookup function; it awaits its first run.
- SBOM generation, release signing/provenance, and independent security audit remain pending.

## Implementation still missing

The source snapshot still lacks the HTTP/TLS gateway, PostgreSQL store, network registration and management CLI commands, Windows identity keystore, runtime and IPC, module ABI, software isolation backend, SDK, KMS/HSM providers, real TEE attestation, remote execution, fuzzing, and release/deployment pipeline. CLI commands `backend detect`, `inspect`, `package build` and local identity/proof-of-possession operations are implemented and tested. These are tracked in [`../ROADMAP.md`](../ROADMAP.md). Hardware-backed behavior will remain unsupported and fail closed until a real verifier is implemented and tested.

No component is declared production-ready by this progress note.

## Additions after this snapshot (unverified)

Added without a Rust toolchain and therefore not covered by the results above: `crates/sers-sdk`, the `fuzz/` targets and the
`fuzz-smoke` CI job, and the design documents `docs/SDK.md`, `docs/MODULE_ABI.md`, `docs/RUNTIME.md`, `docs/BACKENDS.md`,
`docs/API.md` and `docs/DEPLOYMENT.md`. The test count above does not include `sers-sdk` tests. Re-run the full validation.

