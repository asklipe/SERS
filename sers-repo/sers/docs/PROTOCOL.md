# SERS protocol v1

Implementation: `crates/sers-protocol`, `crates/sers-identity`, `control-plane/core`
(NOT VERIFIED: never compiled). **No network transport exists yet**: messages are
Rust types plus strict JSON codecs (`decode` rejects > 16 KiB, unknown/duplicate
fields, uppercase hex, invalid identifiers, wrong versions). TLS 1.3 will be
mandatory for the gateway; it is not implemented.

## Identity

`installation_id = SHA-256("SERS-INSTALLATION-ID-v1\0" || public_key)`. It identifies, it is not a secret.

## 1. Registration (proof of possession)

Client sends `RegistrationRequest {version, application_id, public_key, installation_id, proof}` plus a
license credential. `proof` = Ed25519 signature by the installation key over
`"SERS-REGISTRATION-v1\0" || u16be(version) || len+application_id || public_key || installation_id`.
Server: verifies the proof and that the id derives from the key; application exists and is enabled;
license belongs to the application, is active and unexpired and has a free installation slot;
the installation is unknown (or already active: idempotent). Revoked installations cannot re-register.

## 2. Challenge

`ChallengeRequest {version, application_id, installation_id, package_digest, client_ephemeral_key}`
(fresh X25519 key). Server issues a challenge only to a registered, active installation.
`Challenge` adds `nonce` (256 random bits), `issued_at`, `expires_at` (server clock, <= 300 s).
State is stored server-side and consumed on first verification (ADR 0002).

## 3. Response and decision

`ChallengeResponse {version, nonce, signature}` where the signature covers
`"SERS-AUTH-CHALLENGE-v1\0" || u16be(version) || nonce || len+application_id || installation_id || package_digest || client_ephemeral_key || u64be(issued_at) || u64be(expires_at)`.

The server, in this order: consumes the challenge; checks expiry; looks up the installation key (none
if revoked); verifies the signature; then checks application enabled, installation active and bound to
the application, license usable, package registered for that digest and not revoked, version counter
>= floor; evaluates attestation and policy; and only then releases a key. Denials to the client are
coarse (`InvalidChallenge`, `NotAuthorized`, `HardwareAttestationRequired`); detail goes to the audit log.

Policy: `hardware_required` needs a hardware verdict from the attestation verifier (currently none
exists, so it always fails closed); `remote_execution_required` returns `RemoteOnly` and releases no
key; `software_allowed` accepts the client's unverifiable `process_isolation` claim.

## 4. Grant

* `SignedAuthorization`: Ed25519 signature by the Control Plane authorization key over
  `"SERS-AUTHORIZATION-v1\0" || u16be(version) || token_id || len+application_id || installation_id || package_digest || u8(placement 1=software 2=hardware 3=remote) || u64be(issued_at) || u64be(expires_at)`.
  Lifetime <= 3600 s (default 300 s). Verification checks signature, audience (application, installation, package) and expiry.
* Key release: server and client use ephemeral X25519; shared secret -> HKDF-SHA256 (salt = nonce,
  info = `"SERS-KEY-RELEASE-v1\0" || len+application_id || installation_id || package_digest || client_pub || server_pub`);
  the package key is sealed with AES-256-GCM using that info as AAD. The client key was inside the signed
  challenge, so only the authenticated installation can open it.

## Known gaps

No transport, no channel binding to TLS, no rate limiting, no offline mode. Revocation takes effect at the
next authorization (existing tokens live until `expires_at`). The runtime that enforces token expiry and
guards against local clock rollback does not exist yet. Server-side hardware attestation is not implemented.
