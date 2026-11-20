# Limitations

1. Nothing in this repository has been compiled or executed. Treat every claim as unverified until
   `cargo test --workspace` has been run and its real output recorded in `ROADMAP.md`.
2. A machine that is authorized to run a package receives the package key and the decrypted module. A user with
   debugger or memory access on that machine can observe them. The software profile cannot prevent this
   (T17); a TEE backend does not exist; remote execution is not implemented.
3. No runtime, IPC, execution backend or module ABI exists. Authorization tokens cannot yet be enforced on a client.
4. No network transport: no TLS, no HTTP gateway, no rate limiting.
5. Control Plane state is in memory. The PostgreSQL schema is unexecuted and has no store.
6. Only development key providers exist (master key and token-signing key in process memory). No KMS/HSM.
7. Installation keys are stored in a 0600 file (Unix). They are not hardware-backed, and Windows is unsupported.
8. Hardware attestation is not implemented; `hardware_required` therefore cannot be granted.
9. No fuzzing, dependency auditing, SBOM, provenance or release signing yet.
10. Revocation is checked at authorization time; tokens remain valid until they expire (default 300 s).
