-- SERS Control Plane schema, v1.
-- STATUS: NOT VERIFIED. Never executed against PostgreSQL. The PostgreSQL store
-- that would use it is NOT IMPLEMENTED; the in-memory store in
-- control-plane/core defines the semantics this schema must preserve.
--
-- Notes
--  * Secrets are never stored in clear: API keys and license credentials are
--    stored as SHA-256 hashes, package keys only wrapped by the KMS/HSM.
--  * Application ids are globally unique (a client names only the application).
--  * Row-level security isolates tenants for the management API. The service
--    must connect as a role that is NOT the table owner and must run
--    SET LOCAL sers.tenant_id = '<tenant>' inside each transaction.
--    The client-facing protocol services need a separate, narrowly granted role.
--  * Challenges are single use: consume with
--    DELETE FROM challenges WHERE nonce = $1 RETURNING ...

BEGIN;

CREATE TABLE tenants (
    id         text PRIMARY KEY
               CHECK (length(id) BETWEEN 3 AND 64 AND id ~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    key_hash   bytea PRIMARY KEY CHECK (octet_length(key_hash) = 32),
    tenant_id  text NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id);

CREATE TYPE execution_policy AS ENUM
    ('software_allowed', 'hardware_required', 'remote_execution_required');

CREATE TABLE applications (
    id                  text PRIMARY KEY CHECK (length(id) BETWEEN 3 AND 128),
    tenant_id           text NOT NULL REFERENCES tenants (id),
    execution_policy    execution_policy NOT NULL,
    min_version_counter bigint NOT NULL DEFAULT 0 CHECK (min_version_counter >= 0),
    enabled             boolean NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX applications_tenant_idx ON applications (tenant_id);

CREATE TABLE publisher_keys (
    application_id text NOT NULL REFERENCES applications (id) ON DELETE CASCADE,
    key_id         bytea NOT NULL CHECK (octet_length(key_id) = 32),
    public_key     bytea NOT NULL CHECK (octet_length(public_key) = 32),
    revoked_at     timestamptz,
    PRIMARY KEY (application_id, key_id)
);

CREATE TABLE packages (
    application_id  text NOT NULL REFERENCES applications (id),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    package_id      bytea NOT NULL UNIQUE CHECK (octet_length(package_id) = 16),
    tenant_id       text NOT NULL REFERENCES tenants (id),
    version_counter bigint NOT NULL CHECK (version_counter >= 0),
    wrapped_key     bytea NOT NULL,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, manifest_digest)
);
CREATE INDEX packages_tenant_idx ON packages (tenant_id);

CREATE TYPE license_status AS ENUM ('active', 'suspended', 'revoked');

CREATE TABLE licenses (
    credential_hash   bytea PRIMARY KEY CHECK (octet_length(credential_hash) = 32),
    tenant_id         text NOT NULL REFERENCES tenants (id),
    application_id    text NOT NULL REFERENCES applications (id),
    status            license_status NOT NULL DEFAULT 'active',
    expires_at        timestamptz,
    max_installations integer NOT NULL CHECK (max_installations > 0),
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX licenses_tenant_idx ON licenses (tenant_id);
CREATE INDEX licenses_application_idx ON licenses (application_id);

CREATE TABLE installations (
    id                      bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    tenant_id               text NOT NULL REFERENCES tenants (id),
    application_id          text NOT NULL REFERENCES applications (id),
    license_credential_hash bytea NOT NULL REFERENCES licenses (credential_hash),
    public_key              bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    registered_at           timestamptz NOT NULL DEFAULT now(),
    revoked_at              timestamptz
);
CREATE INDEX installations_tenant_idx ON installations (tenant_id);
CREATE INDEX installations_license_idx ON installations (license_credential_hash);
CREATE INDEX installations_application_idx ON installations (application_id);

CREATE TABLE challenges (
    nonce                bytea PRIMARY KEY CHECK (octet_length(nonce) = 32),
    application_id       text NOT NULL REFERENCES applications (id),
    installation_id      bytea NOT NULL REFERENCES installations (id),
    package_digest       bytea NOT NULL CHECK (octet_length(package_digest) = 32),
    client_ephemeral_key bytea NOT NULL CHECK (octet_length(client_ephemeral_key) = 32),
    issued_at            timestamptz NOT NULL,
    expires_at           timestamptz NOT NULL,
    CHECK (expires_at > issued_at)
);
CREATE INDEX challenges_expiry_idx ON challenges (expires_at);
CREATE INDEX challenges_installation_idx ON challenges (installation_id);

CREATE TABLE authorization_sessions (
    token_id        bytea PRIMARY KEY CHECK (octet_length(token_id) = 32),
    installation_id bytea NOT NULL REFERENCES installations (id),
    application_id  text NOT NULL REFERENCES applications (id),
    package_digest  bytea NOT NULL CHECK (octet_length(package_digest) = 32),
    placement       text NOT NULL CHECK (placement IN ('local_software', 'local_hardware')),
    issued_at       timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    CHECK (expires_at > issued_at)
);
CREATE INDEX authorization_sessions_installation_idx ON authorization_sessions (installation_id);
CREATE INDEX authorization_sessions_expiry_idx ON authorization_sessions (expires_at);

CREATE TABLE revocations (
    id           bigserial PRIMARY KEY,
    tenant_id    text NOT NULL REFERENCES tenants (id),
    subject_type text NOT NULL
                 CHECK (subject_type IN ('installation', 'license', 'package', 'application')),
    subject_id   text NOT NULL,
    reason       text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject_type, subject_id)
);

CREATE TABLE attestation_records (
    id              bigserial PRIMARY KEY,
    installation_id bytea NOT NULL REFERENCES installations (id),
    technology      text NOT NULL CHECK (technology IN ('intel_sgx', 'intel_tdx', 'amd_sev_snp', 'arm_trustzone')),
    verdict         text NOT NULL CHECK (verdict IN ('verified', 'rejected')),
    detail          text,
    evidence_digest bytea CHECK (octet_length(evidence_digest) = 32),
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attestation_records_installation_idx ON attestation_records (installation_id);

CREATE TABLE audit_events (
    seq       bigint PRIMARY KEY,
    at        timestamptz NOT NULL,
    tenant_id text,
    action    text NOT NULL,
    subject   text NOT NULL,
    allowed   boolean NOT NULL,
    detail    text NOT NULL,
    prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash      bytea NOT NULL CHECK (octet_length(hash) = 32)
);
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, seq);

-- Tenant isolation for the management API.
ALTER TABLE api_keys      ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications  ENABLE ROW LEVEL SECURITY;
ALTER TABLE packages      ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses      ENABLE ROW LEVEL SECURITY;
ALTER TABLE installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations   ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON api_keys      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON applications  USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON packages      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON licenses      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON installations USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON revocations   USING (tenant_id = current_setting('sers.tenant_id', true));

COMMIT;
