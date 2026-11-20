# ROADMAP

## Where things stand

All code is **NOT VERIFIED**: it has never been compiled. Step 1 below is mandatory before anything else.
Continue from this repository; do not recreate it.

## 1. Verify what exists (do this first)

Pushing the repository to GitHub is a valid way to start: the CI workflow builds and tests on Linux and Windows,
so its first run is the first real compilation. Expect failures; fix them in dependency order and keep the log.

1. `cargo check --workspace`. Fix compile errors one crate at a time, in dependency order:
   `sers-core` -> `sers-crypto` -> `sers-protocol` -> `sers-identity`, `sers-package` -> `sers-loader`,
   `sers-platform` -> `sers-controlplane`.
2. `cargo test --workspace`. Known-answer tests (RFC 8032 test 1, RFC 5869 case 1, SHA-256 "abc") are
   the first things to inspect: a failure means a typo in the vector or a real bug, never weaken the test.
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all`.
4. Commit `Cargo.lock`. Add `rustfmt.toml`, `deny.toml`; run `cargo audit` and `cargo deny check`.
5. Run `control-plane/migrations/0001_init.sql` against a throwaway PostgreSQL and fix it.
   Also run `cargo run -p sers-controlplane --example protected_flow` and compare with README.md.
6. Record results here (what ran, what passed, what failed). Replace NOT VERIFIED statuses in README.md only for
   what the tests really cover.

Known weak spots to look at first: macro-generated hex newtypes in `sers-core/src/ids.rs`; borrow patterns in
`control-plane/core/src/service.rs` (`authorize`, `revoke_package`); closure typing in `sers-package/src/tests.rs`.

## 2. Next implementation work, in order

1. `sers-integrity` decision (keep hash list in `sers-package` or split) and `sers-inspector` (reads `.sers`).
2. CLI (`sers`, `sers-cli`): `backend detect`, `identity show|register`, `inspect`, `package build|sign`,
   `license create`, `policy configure`, with JSON output and exit codes. Only commands backed by real operations.
3. Control Plane gateway (Axum + Tokio): auth middleware (API key -> tenant), request IDs, validation, security
   headers, rate limiting, TLS 1.3; async `Store` trait and PostgreSQL store (sqlx), transactional challenge
   consumption via `DELETE ... RETURNING`, migrations in CI.
4. Runtime `sersd`: Unix domain socket IPC with peer-credential checks, session manager, token enforcement with
   clock-rollback protection, config loading, graceful shutdown. Windows named pipes behind a platform trait.
5. Module ABI specification (host/core boundary, memory ownership, errors, what the host can observe) and a
   software execution backend (separate process, seccomp, namespaces, rlimits, dropped capabilities), reporting
   only the controls it actually applied. Document that a privileged local attacker is out of scope.
6. SDK: Rust API, then a stable C ABI; Node.js bindings only after the ABI settles.
7. KMS/HSM `KeyProvider` and `TokenSigner` implementations; platform key stores for installation keys.
8. Fuzz targets: package parser, manifest, protocol decoding, IPC messages.
9. Supply chain: `cargo audit`/`deny` in CI, SBOM, release signing (Sigstore/cosign), provenance (SLSA).
10. Deployment: Dockerfiles, Compose, env docs, TLS configuration. Remaining docs: BACKENDS, DEPLOYMENT,
    DEVELOPMENT, API.
11. TEE: choose the first backend from the available hardware (see `docs/TEE_SUPPORT.md`), implement evidence
    generation and a real server-side verifier, and bind key release to the attested environment. Until then
    `hardware_required` fails closed.

## Open decisions

Project license (`LICENSE` not chosen); first TEE target; whether remote execution is the primary strong-
confidentiality path for desktop applications.
