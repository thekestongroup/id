-- Organisations: every account belongs to one. Accounts are
-- username@domain, and each organisation's domain is unique.

CREATE TABLE organisations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    domain          TEXT NOT NULL,
    -- The organisation's own password rules, on top of Keston's baseline
    -- (see internal/policy). {} = baseline only.
    password_policy JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX organisations_domain ON organisations (lower(domain));

ALTER TABLE users
    ADD COLUMN organisation_id UUID REFERENCES organisations (id) ON DELETE RESTRICT,
    -- In their organisation: 'member', or 'global_admin' (manages its
    -- accounts and password policy).
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'global_admin')),
    -- The Keston Group's own staff: can create and manage every organisation.
    ADD COLUMN platform_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- Existing accounts: one organisation per email domain, named after the
-- organisation text they had (or the domain).
INSERT INTO organisations (name, domain)
SELECT DISTINCT ON (lower(split_part(email, '@', 2)))
       coalesce(nullif(organisation, ''), lower(split_part(email, '@', 2))),
       lower(split_part(email, '@', 2))
FROM users
ORDER BY lower(split_part(email, '@', 2)), created_at;

UPDATE users u SET organisation_id = o.id
FROM organisations o
WHERE o.domain = lower(split_part(u.email, '@', 2));

ALTER TABLE users ALTER COLUMN organisation_id SET NOT NULL;
ALTER TABLE users DROP COLUMN organisation;
CREATE INDEX users_organisation ON users (organisation_id);
