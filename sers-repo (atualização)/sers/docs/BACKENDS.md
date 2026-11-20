# Execution backends

Status: design. Today `sers-platform` only inventories backends and reports every one as `implemented: false`.

## Interface

```rust
pub trait ExecutionBackend {
    fn capabilities(&self) -> BackendCapabilities;      // applied controls only
    fn initialize(&self) -> Result<(), SersError>;
    fn attest(&self, nonce: &Nonce32) -> Result<AttestationEvidence, SersError>;  // hardware backends only
    fn load(&self, module: ModulePlaintext, abi: u32) -> Result<ModuleHandle, SersError>;
    fn call(&self, handle: &ModuleHandle, input: &[u8]) -> Result<Vec<u8>, SersError>;
    fn shutdown(&self) -> Result<(), SersError>;
}
```

A backend must not expose an operation it cannot perform; unsupported operations return `SersError::Unsupported`.

## Software backend (planned)

Separate worker process per session, with only the controls the OS really provides, each reported in
`BackendCapabilities` after being applied (never from configuration):

| OS | Candidate controls |
|---|---|
| Linux | `no_new_privs`, seccomp-BPF allow-list, user and network namespaces, rlimits, Landlock filesystem rules |
| Windows | Job Object limits, restricted token or AppContainer, process mitigation policies |
| macOS | App Sandbox profile (limited tooling) |

Limit: a privileged local attacker (same user with debug rights, root, Administrator, kernel) can still inspect the
worker. The software profile is never described as hardware-equivalent.

## Hardware backends

Intel SGX, Intel TDX, AMD SEV-SNP and Arm TrustZone are different technologies with different evidence formats
(`docs/TEE_SUPPORT.md`). Each needs: evidence generation, a server-side verifier with explicit trust roots, measurement
policy, TCB and revocation handling, and key release bound to the attested environment. None is implemented;
`hardware_required` fails closed until one is.

## Remote execution

A separate path: the operation runs on infrastructure the publisher controls; the client receives results, never
keys. Needs an authenticated request contract, rate limiting, abuse controls and an availability and privacy
discussion. Not implemented and not a transparent substitute for local execution.
