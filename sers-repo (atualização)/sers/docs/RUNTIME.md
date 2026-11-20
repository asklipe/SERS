# Runtime `sersd` (design)

Status: **not implemented**. This is the specification the implementation should follow.

## Processes

`sersd` is a per-user supervisor (never root or Administrator). It owns the installation identity, the Control
Plane session and authorization tokens. Protected modules run in separate worker processes (ABI 2) started by `sersd`.
Host applications talk to `sersd` over local IPC.

## IPC

* Linux and macOS: Unix domain socket in a directory with mode 0700 owned by the user.
* Windows: named pipe with a DACL granting access only to the current user SID, remote clients rejected.
* The server authenticates every connection by peer credentials (uid on Unix, token SID on Windows) and refuses
  mismatches. Tokio provides `UnixStream::peer_cred` and `tokio::net::windows::named_pipe`; no `unsafe` is needed.
* Framing: `u32` big-endian length followed by a JSON message, maximum 64 KiB, strict schema (`deny_unknown_fields`),
  versioned. Bounded concurrent connections and per-connection rate limits.

## Requests

`status`, `open { package_path }` (the daemon reads and verifies the file, never the host), `call { session, module, input }`,
`close { session }`. Errors are coarse and carry no secrets.

## Sessions and tokens

A session holds the opened package, the package key (zeroized on close) and the signed authorization. Every `call`
checks token expiry against a monotonic clock and the high-water mark of observed time; an expired or rolled-back
clock ends the session. Tokens are never exposed to the host application.

## Policy

`hardware_required` without a verified backend fails closed. The runtime reports only the controls the backend actually
applied (`BackendCapabilities`), never configuration claims. Logging is structured and never includes keys, plaintext or
license credentials.

## Shutdown and failure

Graceful shutdown closes sessions, zeroizes keys and terminates workers. If `sersd` dies, workers exit (parent-death
handling); the host must re-open.

## Open items

Module ABI 2 runtime, worker sandboxes (`docs/BACKENDS.md`), service installation per OS, update channel (TUF),
installation key storage in the platform store.
