-- SAML 2.0 apps (service providers). Each is also a row in clients
-- (protocol 'saml'), so app access (Forced/Enabled/Disabled) works the same.
CREATE TABLE saml_apps (
    client_id    TEXT PRIMARY KEY REFERENCES clients (id) ON DELETE CASCADE,
    -- The app's entity ID, unique within its organisation.
    entity_id    TEXT NOT NULL,
    -- Where its metadata came from ('' when typed in), and the metadata XML
    -- (made from the entity ID and ACS URL when typed in).
    metadata_url TEXT NOT NULL DEFAULT '',
    metadata     TEXT NOT NULL,
    acs_url      TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Keston ID's SAML signing certificate. The private key is encrypted with
-- KESTON_ID_SECRET_KEY, like the OIDC signing keys.
CREATE TABLE saml_certificates (
    id          TEXT PRIMARY KEY,
    certificate BYTEA NOT NULL, -- DER
    private_key BYTEA NOT NULL, -- encrypted PKCS#8
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);

-- A SAML sign-in waiting for someone to sign in: the original request (the
-- query string or form it arrived with), replayed once they have.
ALTER TABLE auth_requests ADD COLUMN saml_request TEXT NOT NULL DEFAULT '';
