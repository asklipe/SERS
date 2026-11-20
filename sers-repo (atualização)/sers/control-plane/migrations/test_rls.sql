-- Smoke test for CI only. Run after 0001_init.sql against a disposable DB.
-- The normal application login roles are created and granted out of band;
-- this role models the table privileges assigned to a management service.
CREATE ROLE sers_ci_manager NOLOGIN;
GRANT SELECT ON tenants, api_keys, applications TO sers_ci_manager;

INSERT INTO tenants (id) VALUES ('tenant-a'), ('tenant-b');
INSERT INTO applications (id, tenant_id, execution_policy) VALUES
    ('tenant-a.editor', 'tenant-a', 'software_allowed'),
    ('tenant-b.editor', 'tenant-b', 'software_allowed');
INSERT INTO api_keys (key_hash, tenant_id) VALUES
    (decode(repeat('a', 64), 'hex'), 'tenant-a'),
    (decode(repeat('b', 64), 'hex'), 'tenant-b');

DO $$
BEGIN
    BEGIN
        INSERT INTO packages (
            application_id, manifest_digest, package_id, tenant_id,
            version_counter, wrapped_key
        ) VALUES (
            'tenant-a.editor', decode(repeat('c', 64), 'hex'),
            decode(repeat('d', 32), 'hex'), 'tenant-b', 1,
            decode(repeat('e', 120), 'hex')
        );
        RAISE EXCEPTION 'cross-tenant package reference was accepted';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;
END
$$;

SET ROLE sers_ci_manager;
BEGIN;
SET LOCAL sers.tenant_id = 'tenant-a';
DO $$
BEGIN
    IF (SELECT count(*) FROM tenants) <> 1 THEN
        RAISE EXCEPTION 'tenant RLS did not isolate tenants';
    END IF;
    IF (SELECT count(*) FROM applications) <> 1 THEN
        RAISE EXCEPTION 'application RLS did not isolate tenants';
    END IF;
    IF (SELECT count(*) FROM api_keys) <> 1 THEN
        RAISE EXCEPTION 'API key RLS did not isolate tenants';
    END IF;
END
$$;
COMMIT;
RESET ROLE;

-- The pre-auth lookup role receives function execution only, not table access.
SET ROLE sers_auth;
DO $$
DECLARE
    resolved_tenant text;
BEGIN
    SELECT tenant_id INTO resolved_tenant
    FROM sers_resolve_api_key(decode(repeat('a', 64), 'hex'));
    IF resolved_tenant IS DISTINCT FROM 'tenant-a' THEN
        RAISE EXCEPTION 'API key lookup returned the wrong tenant';
    END IF;
END
$$;
RESET ROLE;
