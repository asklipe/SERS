# TEE support

**Supported TEE technologies today: none.** `sers-platform` can notice device nodes; that is detection only.
No attestation evidence is produced or verified, and every backend is reported `implemented: false`.

The technologies below are not interchangeable. The notes are general background and were **not re-checked
against current vendor documentation in this session**; verify before relying on them.

| Technology | Isolation unit | Evidence | Verification path (to confirm) | Device node probed |
|---|---|---|---|---|
| Intel SGX | process-level enclave | ECDSA quote (DCAP) | Intel DCAP collateral / PCS or Trust Authority | `/dev/sgx_enclave` |
| Intel TDX | confidential VM (trust domain) | TD quote | DCAP-style verification of the quote | `/dev/tdx_guest` |
| AMD SEV-SNP | confidential VM | attestation report signed with the VCEK | AMD KDS certificate chain, TCB checks | `/dev/sev-guest` |
| Arm TrustZone | secure world, TEE OS (e.g. OP-TEE) | vendor specific, no common standard | vendor specific | `/dev/tee0` |
| TPM 2.0 (not a TEE) | measured boot, key storage | PCR quote | TPM quote + event log policy | `/dev/tpmrm0` |

## What a real backend needs

Evidence generation on the client; verification on the server against explicit trust roots; measurement policy
for the protected module; freshness (a verifier-chosen nonce bound into the evidence); TCB status and
revocation handling; and key release **only** to the attested environment (the current key release seals to an
ephemeral key proven only by the installation signature, which is not enough for `hardware_required`).
The attestation verifier interface (`AttestationVerifier`) exists; the only shipped implementation never
verifies anything, so hardware-required applications fail closed.

## Feasibility observations (to validate before choosing a first backend)

* VM-level TEEs (TDX, SEV-SNP) protect a guest from the host or hypervisor. They do not protect a desktop
  application from the user who owns that desktop. They fit company-controlled infrastructure, that is,
  the `remote_execution_required` mode, rather than end-user machines.
* Process-level enclaves (SGX) fit the end-user model on paper, but availability on consumer CPUs is limited
  (Intel stopped offering SGX on recent Core client parts; it remains a server feature). Check the hardware
  you actually have.
* The first backend should follow the available development hardware and its attestation infrastructure.
  That decision is open and tracked in `ROADMAP.md`.
