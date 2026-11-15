-- Groups of users within an organisation, e.g. "Teachers", "Office".
CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX groups_name ON groups (organisation_id, lower(name));

CREATE TABLE group_members (
    group_id UUID NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members (user_id);

-- App access, per organisation: the default (group_id NULL), overridden
-- per group.
--   forced:   on, and people can't turn it off
--   enabled:  on, and each person can turn it off (remove it)
--   disabled: off, and people can't use it
-- No row: Keston's own apps are forced; other apps are up to each person
-- (they add one by signing in to it).
CREATE TABLE app_policies (
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    group_id        UUID REFERENCES groups (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    mode            TEXT NOT NULL CHECK (mode IN ('forced', 'enabled', 'disabled')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX app_policies_one ON app_policies
    (organisation_id, coalesce(group_id, '00000000-0000-0000-0000-000000000000'), client_id);

-- Carry over the earlier organisation apps: enabled for everyone → forced,
-- optional → enabled.
INSERT INTO app_policies (organisation_id, client_id, mode)
SELECT organisation_id, client_id, CASE mode WHEN 'enabled' THEN 'forced' ELSE 'enabled' END
FROM organisation_apps;
DROP TABLE organisation_apps;
