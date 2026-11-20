# Development

Requirements: stable Rust with Cargo 1.78 or newer to read the generated lockfile. `[workspace.lints]` itself requires Cargo 1.74 or newer.
Network access is needed for the first build to fetch crates. Commit the generated `Cargo.lock`.

```sh
cargo build --workspace --all-targets
cargo test --workspace
cargo run -p sers-controlplane --example protected_flow
cargo run -p sers-cli -- package build build.json dist/app.sers
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Layout

* `crates/sers-core` -> `sers-crypto` -> `sers-protocol` -> `sers-identity`, `sers-package` -> `sers-loader`
* `crates/sers-platform` (independent probing)
* `control-plane/core` (`sers-controlplane`) depends on core, crypto, protocol and package; `sers-identity` is a dev-dependency used by tests and the example
* `control-plane/migrations` PostgreSQL schema, not executed by any code yet
* `crates/sers-cli` backend diagnostics, verified inspection, and bounded package builder

## Conventions

* `unsafe_code = "forbid"` for the whole workspace.
* Errors are `SersError` with static messages; never embed secrets or attacker-controlled data.
* Signed or hashed bytes are canonical binary with a distinct domain tag; never sign JSON.
* Secrets use `Zeroizing` / `ZeroizeOnDrop` and redacted `Debug`.
* Time is injected as `now: u64` (Unix seconds) so tests are deterministic.
* Every negative security property gets a test, named after the property.

## Known-answer tests

`sers-crypto` contains SHA-256("abc"), RFC 8032 Ed25519 test 1 and RFC 5869 HKDF case 1. If one fails, compare the
vector with the RFC before touching the code. Never weaken or delete such a test.

## CI

`.github/workflows/ci.yml` builds and tests on Linux and Windows, blocks on formatting and clippy failures, audits
dependencies, and applies the PostgreSQL migration plus its RLS and lookup-function smoke test. Hardware-dependent
checks (TEE evidence generation and verification) cannot run on generic runners and do not exist yet.
