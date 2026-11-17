-- App access rules (Keston Admin → Apps → an app → Access) and Keston-wide
-- apps managed in Keston Admin.
--
-- App access is now an organisation's default for each app (app_policies,
-- group_id NULL: unchanged) plus ordered rules per app, like the MFA custom
-- rules: the first turned-on rule whose conditions all match (users, groups,
-- IP addresses; empty matches anyone) decides Forced, Enabled or Disabled;
-- no match: the default.
CREATE TABLE app_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    position        INT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    mode            TEXT NOT NULL CHECK (mode IN ('forced', 'enabled', 'disabled')),
    user_ids        UUID[] NOT NULL DEFAULT '{}',
    group_ids       UUID[] NOT NULL DEFAULT '{}',
    ip_ranges       CIDR[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX app_rules_app ON app_rules (organisation_id, client_id, position);

-- Today's per-group settings become rules (one per group per app), keeping
-- their effect. When someone's groups disagreed, Disabled won, then Forced,
-- then Enabled: so those rules go in that order (then by group name), and
-- the first match decides the same way. Group settings beat the default,
-- and so do rules (no match: the default).
INSERT INTO app_rules (organisation_id, client_id, name, position, mode, group_ids)
SELECT p.organisation_id, p.client_id, g.name,
       row_number() OVER (PARTITION BY p.organisation_id, p.client_id
                          ORDER BY CASE p.mode WHEN 'disabled' THEN 1 WHEN 'forced' THEN 2 ELSE 3 END, lower(g.name)),
       p.mode, ARRAY[p.group_id]
FROM app_policies p JOIN groups g ON g.id = p.group_id
WHERE p.group_id IS NOT NULL;
DELETE FROM app_policies WHERE group_id IS NOT NULL;

-- Keston-wide apps: registered from deploy/clients.json ('deployment', as
-- all of them are today) or created and edited by TKG Admins in Keston
-- Admin ('admin': `keston-id clients sync` never overwrites those). Apps an
-- organisation adds itself are 'admin'. A retired app (retired_at) is no
-- longer shown or signed in to.
ALTER TABLE clients
    ADD COLUMN description TEXT NOT NULL DEFAULT '',
    ADD COLUMN managed_by  TEXT NOT NULL DEFAULT 'admin' CHECK (managed_by IN ('deployment', 'admin')),
    ADD COLUMN retired_at  TIMESTAMPTZ;
UPDATE clients SET managed_by = 'deployment' WHERE organisation_id IS NULL;
