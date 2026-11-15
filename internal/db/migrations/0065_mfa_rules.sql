-- MFA custom rules (Keston Admin → Security → Manage MFA), used when the
-- organisation's MFA mode is 'custom'. Tried in order; the first enabled
-- rule whose conditions all match decides (require MFA, or not). Empty
-- conditions match anyone. No match: organisations.mfa_required ("Everyone
-- else").
CREATE TABLE mfa_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    position        INT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    require_mfa     BOOLEAN NOT NULL,
    user_ids        UUID[] NOT NULL DEFAULT '{}',
    group_ids       UUID[] NOT NULL DEFAULT '{}',
    client_ids      TEXT[] NOT NULL DEFAULT '{}',
    ip_ranges       CIDR[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX mfa_rules_organisation ON mfa_rules (organisation_id, position);

-- Today's per-group settings become rules, keeping their effect: a group
-- requiring MFA wins over one that doesn't, so those come first.
INSERT INTO mfa_rules (organisation_id, name, position, require_mfa, group_ids)
SELECT g.organisation_id, g.name, row_number() OVER (PARTITION BY g.organisation_id ORDER BY NOT g.mfa_required, lower(g.name)),
       g.mfa_required, ARRAY[g.id]
FROM groups g WHERE g.mfa_required IS NOT NULL;

-- A rule (e.g. for one app) said MFA is needed in this session: kept, so
-- setting it up isn't forgotten on the next request.
ALTER TABLE sessions ADD COLUMN mfa_enrol_required BOOLEAN NOT NULL DEFAULT FALSE;
