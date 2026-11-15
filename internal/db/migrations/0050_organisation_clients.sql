-- Apps an organisation adds itself in Keston Admin (its own SSO apps):
-- only its users can sign in to them, and they skip the consent prompt
-- (the organisation set them up). NULL: an app registered by Keston
-- (deploy/clients*.json), usable by any organisation.
ALTER TABLE clients
    ADD COLUMN organisation_id UUID REFERENCES organisations (id) ON DELETE CASCADE,
    -- 'oidc' (OpenID Connect) or 'saml' (SAML 2.0, see saml_apps).
    ADD COLUMN protocol        TEXT NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'saml')),
    ADD COLUMN logo_url        TEXT NOT NULL DEFAULT '',
    -- Organisation apps that use PKCE without a secret: single-page or mobile.
    ADD COLUMN native          BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX clients_organisation ON clients (organisation_id) WHERE organisation_id IS NOT NULL;
