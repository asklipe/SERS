# Control Plane HTTP API (design)

Status: **not implemented**; the in-process `ControlPlane` in `control-plane/core` defines the semantics.

Transport: TLS 1.3 only. The service binds to loopback by default and refuses a non-loopback address unless TLS is
configured or the operator passes an explicit insecure flag intended for development. Versioned prefix `/v1`.
Request size cap 64 KiB (package upload excluded). Strict JSON (`deny_unknown_fields`), request ids, security
headers, per-IP and per-key rate limits, structured errors without internals.

## Client-facing (no API key; authenticated by the protocol)

| Method and path | Body | Result |
|---|---|---|
| `POST /v1/installations` | `{ registration: RegistrationRequest, license }` | `204` |
| `POST /v1/challenges` | `ChallengeRequest` | `Challenge` |
| `POST /v1/authorizations` | `{ response: ChallengeResponse, process_isolation: bool }` | `{ decision: "granted", authorization, key_release }`, `{ decision: "remote_only" }` or `{ decision: "denied", reason }` |

`key_release` is `{ server_public_key, sealed_key }` in lowercase hex. Attestation evidence is added only when a real
verifier exists. `authorizations` must not be retried: a challenge is single use. Reasons are coarse
(`invalid_challenge`, `not_authorized`, `hardware_attestation_required`).

## Management (Bearer API key, tenant-scoped)

Tenants, applications and publisher keys, package registration (upload plus package key over TLS), licenses
(create, suspend, revoke), installation revocation, minimum version floors, and audit export. Every operation is
scoped to the authenticated tenant; cross-tenant access answers `404`.

## Operational

`GET /healthz` (liveness) and `GET /readyz` (database and key provider reachable). Metrics and tracing through
OpenTelemetry. The audit chain should be shipped to append-only external storage.
