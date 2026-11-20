# Rust SDK (`sers-sdk`)

Status: written after the validated snapshot, **NOT VERIFIED** (never compiled). Run `cargo fmt --all`, `cargo clippy`
and `cargo test -p sers-sdk` before relying on it.

```rust
let app = SersApplicationBuilder::new()
    .application_id(ApplicationId::new("acme.editor")?)
    .license(license)                       // activation credential from the publisher
    .trust_publisher(publisher_public_key)  // at least one
    .authority_key(control_plane_key)       // verifies signed authorizations
    .key_store(Box::new(FileKeyStore::new(path)))   // or .identity(..)
    .claim_process_isolation(false)         // true only if the host really isolates
    .build(my_transport)?;                  // Transport: HTTP over TLS in production

app.initialize()?;                          // registration, idempotent
let opened = app.open(std::fs::read("app.sers")?)?;
let module = app.module(&opened, &ModuleId::new("core")?)?;   // Zeroizing<Vec<u8>>
```

`open` performs: publisher trust, application match, revocation, downgrade floor and module-hash checks (loader);
challenge request with a fresh X25519 key; a check that the returned challenge matches the request; the signed
response; the Control Plane decision; verification of the signed authorization (signature, audience, lifetime,
local placement); opening of the sealed package key; and a check that the key unwraps every module.
`module` re-checks expiry on every call using a clock that never goes backwards within the process.

Guarantees and limits:

* A denied, remote-only or invalid grant is an error; there is no silent fallback.
* `hardware_required` packages cannot be opened today (no verifier exists).
* The decrypted module lives in this process. This is ABI 1 (`docs/MODULE_ABI.md`): it gates distribution and
  use, it does not isolate execution. A debugger on this machine can read it (`docs/THREAT_MODEL.md`, T17).
* Clock rollback detection covers one process lifetime. A restart forgets the high-water mark.
* `Transport` implementations must authenticate the server, use TLS 1.3, and never retry `authorize`.
* The C ABI and Node.js bindings are not implemented (the workspace forbids `unsafe`; a C ABI needs a separate,
  reviewed crate).
