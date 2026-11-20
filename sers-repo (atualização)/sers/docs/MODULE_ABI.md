# Module ABI

Status: **specification**. ABI 1 is what `sers-sdk` implements today; ABI 2 and 3 are proposals, not implemented.
The `abi_version` field of a manifest module entry selects the ABI.

## ABI 1: data module (implemented in the SDK)

The module is an opaque byte string. After authorization the host receives the plaintext in its own process.
It protects distribution, licensing and key release. It provides **no** execution isolation: whoever controls the
machine can read the plaintext once it is decrypted. Use it for assets, configuration, model weights and
algorithm parameters where gated delivery is the goal.

## ABI 2: WebAssembly module in a worker process (proposed)

Goal: run protected logic without handing its source to the host application.

* The module is a WebAssembly core module (no WASI, no threads, no host filesystem or network).
* A separate worker process (`sers-worker`) loads it with an interpreter or JIT, with memory, fuel and wall-clock
  limits; the host never receives the module bytes, only call results.
* Exports: `sers_alloc(len: i32) -> i32`, `sers_call(ptr: i32, len: i32) -> i32` (status), `sers_result_ptr() -> i32`,
  `sers_result_len() -> i32`. The host copies the request into module memory, calls, then copies the result out.
  Status 0 is success; non-zero values are module-defined errors in `1..=127`; negative values are reserved for the runtime.
* Imports: only `sers_log(level, ptr, len)`, bounded and rate limited. No clock, randomness, files or network.
  State that must persist is passed in and out explicitly by the host as opaque blobs.
* Limits (defaults, configurable by policy): 64 MiB memory, 1 MiB request, 1 MiB result, 10 s per call,
  deterministic fuel budget.
* Everything the host can observe: requests, results, call timing and sizes, and the worker's resource use.
  Timing and size side channels are out of scope.

What it does not do: a privileged local attacker can still read the worker's memory. Only a verified TEE or
remote execution changes that.

## ABI 3: enclave module (hardware only, undefined)

Depends on the first TEE backend (`docs/TEE_SUPPORT.md`). Not specified.

## Rules for any ABI

Inputs and outputs are length-bounded and validated; memory ownership is explicit (caller allocates, callee does not
retain pointers); errors never include secrets; the decrypted module is zeroized after load where the platform allows.
