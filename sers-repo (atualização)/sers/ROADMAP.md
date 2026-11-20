# ROADMAP

## Current status

Validation milestone completed on Windows x64 on 2026-11-20. The workspace builds, all 148 tests pass, formatting is clean, Clippy passes with warnings denied, the CLI and protected-flow example pass, and `cargo audit` reports no advisories. `cargo deny check` passed before this turn; it could not refresh its advisory cache in the sandbox. A PostgreSQL CI smoke test now covers tenant RLS and pre-auth lookup permissions, pending its first CI run. This is source-level project validation, not a security audit or production-readiness claim. See [`docs/PROGRESS.md`](docs/PROGRESS.md) for commands and platform limits.

Remaining validation: Linux CI and Unix-only keystore tests; PostgreSQL migration against a real disposable server; independent security review. Cargo-deny reports a non-failing duplicate `syn` 2.x/3.x warning.

## Unverified additions since the validated snapshot

Written without a Rust toolchain, so **not compiled, not formatted, not tested**:

- `crates/sers-sdk` (client API, `docs/SDK.md`) and its tests.
- `fuzz/` (five cargo-fuzz targets) and the `fuzz-smoke` CI job.
- Design documents: `docs/MODULE_ABI.md`, `docs/RUNTIME.md`, `docs/BACKENDS.md`, `docs/API.md`, `docs/DEPLOYMENT.md`.

Next action: `cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`,
fix what fails, then `cargo +nightly fuzz run package_parse -- -max_total_time=60` for each target. Update this file with the
real results.

## Completed first milestone

1. `cargo check --workspace` and `cargo build --workspace --all-targets` pass.
2. `cargo test --workspace` passes: 148 tests, zero failures on Windows x64.
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes.
4. `cargo fmt --all -- --check` passes; `Cargo.lock` is generated.
5. The protected-flow example passes, including package encryption, authorization, revocation, fail-closed hardware policy, and audit-chain verification.
6. CI formatting, Clippy, RustSec audit, and cargo-deny checks now block on failure.
7. `deny.toml` allows only the permissive third-party licenses encountered; unpublished project crates remain excluded while the owner decides the project license.

Not completed in this milestone: PostgreSQL migration validation and Linux CI. PostgreSQL and Docker are not installed in the current environment.

## Implementation roadmap

1. Package inspection, `backend detect`, `package build`, and local identity/proof-of-possession commands are implemented. Add a protected Windows keystore and network registration operations.
2. Specify and implement the Control Plane gateway with authentication, request IDs, strict input validation, security headers, rate limiting, and TLS 1.3.
3. Add an async storage interface and PostgreSQL implementation. Consume challenges transactionally and add migration integration tests.
4. Specify the module ABI and host/core boundary before building `sersd`, IPC, token enforcement, and session management.
5. Implement a software-isolation backend only for controls the OS can actually enforce; report applied controls and keep privileged local attackers out of the claimed protection boundary.
6. Add SDKs after the ABI stabilizes; add KMS/HSM key and token-signing providers.
7. Add fuzz targets for package parsing, manifests, protocol decoding, and IPC.
8. Dependency policy is configured and audited locally. Add SBOM, release signing, build provenance, and deployment artifacts.
9. Implement a TEE only after selecting available development hardware and an attestation verification path. Bind key release to verified evidence. `hardware_required` must continue to fail closed until this is done.
10. Treat remote execution as a separate confidentiality path with an explicit service contract and deployment model.

## Open product decisions

- Project license; no `LICENSE` file is included in the supplied snapshot.
- First TEE target and available hardware/attestation service.
- Whether remote execution is the primary strong-confidentiality path for desktop applications.
- Target deployment model and operational owner for the Control Plane.
