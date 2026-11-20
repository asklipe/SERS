-- SERS Control Plane schema, v1.
-- STATUS: a disposable PostgreSQL CI job is configured but has not run yet. The
-- PostgreSQL store that would use it is NOT IMPLEMENTED; the in-memory store
-- in control-plane/core defines the semantics this schema must preserve.
--
-- Notes
--  * Secrets are never stored in clear: API keys and license credentials are
--    stored as SHA-256 hashes, package keys only wrapped by the KMS/HSM.
--  * Application ids are globally unique (a client names only the application).
--  * Row-level security is defense in depth for management queries. The
--    service must connect as a role that is NOT the table owner and must run
--    SET LOCAL sers.tenant_id = '<tenant>' inside each transaction. A custom
--    setting is writable by that database role, so RLS is not a boundary
--    against a compromised login or arbitrary SQL execution; the gateway
--    must authenticate the API key and bind the tenant context.
--    Pre-authentication needs narrow SECURITY DEFINER lookups to discover the
--    tenant from an API-key hash, installation id, or license hash before the
--    service can set that tenant context. Those lookups are granted only to
--    separate non-login roles; service login roles receive membership out of band.
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

CREATE ROLE sers_auth NOLOGIN;
CREATE FUNCTION sers_resolve_api_key(p_key_hash bytea)
RETURNS TABLE (tenant_id text, key_revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT k.tenant_id, k.revoked_at
    FROM public.api_keys AS k
    WHERE k.key_hash = p_key_hash
$$;
REVOKE ALL ON FUNCTION sers_resolve_api_key(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sers_resolve_api_key(bytea) TO sers_auth;

CREATE TYPE execution_policy AS ENUM
    ('software_allowed', 'hardware_required', 'remote_execution_required');

CREATE TABLE applications (
    id                  text PRIMARY KEY CHECK (length(id) BETWEEN 3 AND 128),
    tenant_id           text NOT NULL REFERENCES tenants (id),
    execution_policy    execution_policy NOT NULL,
    min_version_counter bigint NOT NULL DEFAULT 0 CHECK (min_version_counter >= 0),
    enabled             boolean NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
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
    application_id  text NOT NULL,
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest) = 32),
    package_id      bytea NOT NULL UNIQUE CHECK (octet_length(package_id) = 16),
    tenant_id       text NOT NULL,
    version_counter bigint NOT NULL CHECK (version_counter >= 0),
    wrapped_key     bytea NOT NULL CHECK (octet_length(wrapped_key) = 60),
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, manifest_digest),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
);
CREATE INDEX packages_tenant_idx ON packages (tenant_id);

CREATE TYPE license_status AS ENUM ('active', 'suspended', 'revoked');

CREATE TABLE licenses (
    credential_hash   bytea PRIMARY KEY CHECK (octet_length(credential_hash) = 32),
    tenant_id         text NOT NULL REFERENCES tenants (id),
    application_id    text NOT NULL,
    status            license_status NOT NULL DEFAULT 'active',
    expires_at        timestamptz,
    max_installations integer NOT NULL CHECK (max_installations > 0),
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, application_id, credential_hash),
    FOREIGN KEY (tenant_id, application_id) REFERENCES applications (tenant_id, id)
);
CREATE INDEX licenses_tenant_idx ON licenses (tenant_id);
CREATE INDEX licenses_application_idx ON licenses (application_id);

CREATE TABLE installations (
    id                      bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    tenant_id               text NOT NULL REFERENCES tenants (id),
    application_id          text NOT NULL,
    license_credential_hash bytea NOT NULL,
    public_key              bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    registered_at           timestamptz NOT NULL DEFAULT now(),
    revoked_at              timestamptz,
    UNIQUE (id, application_id),
    FOREIGN KEY (tenant_id, application_id, license_credential_hash)
        REFERENCES licenses (tenant_id, application_id, credential_hash)
);
CREATE INDEX installations_tenant_idx ON installations (tenant_id);
CREATE INDEX installations_license_idx ON installations (license_credential_hash);
CREATE INDEX installations_application_idx ON installations (application_id);

CREATE ROLE sers_protocol NOLOGIN;
CREATE FUNCTION sers_resolve_installation(p_id bytea)
RETURNS TABLE (tenant_id text, application_id text, installation_status text, public_key bytea)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT i.tenant_id, i.application_id, i.status, i.public_key
    FROM public.installations AS i
    WHERE i.id = p_id
$$;
CREATE FUNCTION sers_resolve_license(p_credential_hash bytea)
RETURNS TABLE (
    tenant_id text,
    application_id text,
    license_status public.license_status,
    expires_at timestamptz,
    max_installations integer
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT l.tenant_id, l.application_id, l.status, l.expires_at, l.max_installations
    FROM public.licenses AS l
    WHERE l.credential_hash = p_credential_hash
$$;
REVOKE ALL ON FUNCTION sers_resolve_installation(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION sers_resolve_license(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sers_resolve_installation(bytea) TO sers_protocol;
GRANT EXECUTE ON FUNCTION sers_resolve_license(bytea) TO sers_protocol;

CREATE TABLE challenges (
    nonce                bytea PRIMARY KEY CHECK (octet_length(nonce) = 32),
    application_id       text NOT NULL,
    installation_id      bytea NOT NULL,
    package_digest       bytea NOT NULL CHECK (octet_length(package_digest) = 32),
    client_ephemeral_key bytea NOT NULL CHECK (octet_length(client_ephemeral_key) = 32),
    issued_at            timestamptz NOT NULL,
    expires_at           timestamptz NOT NULL,
    CHECK (expires_at > issued_at),
    FOREIGN KEY (installation_id, application_id)
        REFERENCES installations (id, application_id),
    FOREIGN KEY (application_id, package_digest)
        REFERENCES packages (application_id, manifest_digest)
);
CREATE INDEX challenges_expiry_idx ON challenges (expires_at);
CREATE INDEX challenges_installation_idx ON challenges (installation_id);

CREATE TABLE authorization_sessions (
    token_id        bytea PRIMARY KEY CHECK (octet_length(token_id) = 32),
    installation_id bytea NOT NULL,
    application_id  text NOT NULL,
    package_digest  bytea NOT NULL CHECK (octet_length(package_digest) = 32),
    placement       text NOT NULL CHECK (placement IN ('local_software', 'local_hardware')),
    issued_at       timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    CHECK (expires_at > issued_at),
    FOREIGN KEY (installation_id, application_id)
        REFERENCES installations (id, application_id),
    FOREIGN KEY (application_id, package_digest)
        REFERENCES packages (application_id, manifest_digest)
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
ALTER TABLE tenants               ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys      ENABLE ROW LEVEL SECURITY;
ALTER TABLE applications  ENABLE ROW LEVEL SECURITY;
ALTER TABLE publisher_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE packages      ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses      ENABLE ROW LEVEL SECURITY;
ALTER TABLE installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations   ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestation_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenants      USING (id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON api_keys      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON applications  USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON publisher_keys USING (
    EXISTS (SELECT 1 FROM applications a
            WHERE a.id = publisher_keys.application_id
              AND a.tenant_id = current_setting('sers.tenant_id', true))
);
CREATE POLICY tenant_isolation ON packages      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON licenses      USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON installations USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON challenges USING (
    EXISTS (SELECT 1 FROM installations i
            WHERE i.id = challenges.installation_id
              AND i.tenant_id = current_setting('sers.tenant_id', true))
);
CREATE POLICY tenant_isolation ON authorization_sessions USING (
    EXISTS (SELECT 1 FROM installations i
            WHERE i.id = authorization_sessions.installation_id
              AND i.tenant_id = current_setting('sers.tenant_id', true))
);
CREATE POLICY tenant_isolation ON revocations   USING (tenant_id = current_setting('sers.tenant_id', true));
CREATE POLICY tenant_isolation ON attestation_records USING (
    EXISTS (SELECT 1 FROM installations i
            WHERE i.id = attestation_records.installation_id
              AND i.tenant_id = current_setting('sers.tenant_id', true))
);
CREATE POLICY tenant_isolation ON audit_events USING (
    tenant_id = current_setting('sers.tenant_id', true)
);

COMMIT;
