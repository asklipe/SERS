# Deployment

Status: **nothing is deployable yet.** There is no HTTP gateway, no PostgreSQL store, no runtime and no KMS provider.
This document records the intended shape so the pieces can be built to fit.

Target topology: TLS-terminating gateway -> Control Plane service -> PostgreSQL, with a KMS/HSM for the master
key and the authorization-signing key. Management and protocol traffic use different database roles; protocol roles
get narrow grants and the `SECURITY DEFINER` lookup functions in `control-plane/migrations`.

Configuration (planned, environment variables): database URL and CA, KMS key identifiers, TLS certificate and key
paths, listen address, rate limits, challenge and authorization lifetimes. Secrets come from the secret manager or
mounted files, never from the repository or example files.

Database: apply `control-plane/migrations/0001_init.sql`. The CI job `PostgreSQL migration` applies it to a disposable
server and runs `test_rls.sql`; production roles must not own the tables.

Container images and Compose files will be added with the gateway; examples will contain no real credentials.
The `LocalDevKeyProvider` and the in-memory store are for development and tests only.
