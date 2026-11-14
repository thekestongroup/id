-- Which apps people see under Connected apps, and who put them there:
--   - Keston's own apps (builtin): every organisation has them.
--   - Apps an organisation adds: "enabled" (everyone has it, can't remove)
--     or "optional" (shown to everyone, each person can remove it).
--   - Apps someone signed in to themselves: from their grants.

ALTER TABLE clients ADD COLUMN builtin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE organisation_apps (
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    mode            TEXT NOT NULL CHECK (mode IN ('enabled', 'optional')),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organisation_id, client_id)
);

-- Optional organisation apps someone has removed for themselves.
CREATE TABLE removed_apps (
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    removed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
