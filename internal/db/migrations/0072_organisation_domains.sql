-- Several domains per organisation.
--
-- organisation_domains is the source of truth for "which organisation owns
-- this domain". organisations.domain stays as a copy of the primary domain
-- (the store keeps the two in step in one transaction), so everything that
-- only needs "the" domain (new users' default, support accounts, listings)
-- keeps working unchanged.
--
-- A domain is unique across all of Keston, whether verified or not (an
-- unverified one is reserved by the organisation that added it), and exactly
-- one domain per organisation is primary, which must be verified.

CREATE TABLE organisation_domains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id     UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    domain              TEXT NOT NULL CHECK (domain = lower(domain)),
    is_primary          BOOLEAN NOT NULL DEFAULT FALSE,
    status              TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified', 'verified')),
    -- keston-verify=<token> in a TXT record proves control of the domain.
    verification_token  TEXT NOT NULL,
    verified_at         TIMESTAMPTZ,
    verified_by         UUID REFERENCES users (id) ON DELETE SET NULL,
    verified_by_name    TEXT NOT NULL DEFAULT '',
    -- Verified by a TKG Admin without DNS (verified_by says who).
    verified_by_override BOOLEAN NOT NULL DEFAULT FALSE,
    added_by            UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT is_primary OR status = 'verified'),
    CHECK (status = 'unverified' OR verified_at IS NOT NULL)
);
CREATE UNIQUE INDEX organisation_domains_domain ON organisation_domains (lower(domain));
CREATE UNIQUE INDEX organisation_domains_primary ON organisation_domains (organisation_id) WHERE is_primary;
CREATE INDEX organisation_domains_org ON organisation_domains (organisation_id);

-- Every existing domain becomes its organisation's verified primary domain.
INSERT INTO organisation_domains (organisation_id, domain, is_primary, status, verification_token, verified_at)
SELECT id, lower(domain), TRUE, 'verified', replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
       now()
FROM organisations;
