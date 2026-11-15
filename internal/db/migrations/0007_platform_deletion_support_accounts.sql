-- The Keston Group's own organisation (the platform organisation): its
-- global admins (and anyone there marked platform_admin) are Keston staff,
-- who see every organisation and can ask for support access. There's
-- exactly one, and it can't be deleted.
ALTER TABLE organisations ADD COLUMN is_platform BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX organisations_one_platform ON organisations (is_platform) WHERE is_platform;

-- Deleting an organisation waits 14 days (delete_after). A global admin
-- signing in before then cancels it.
ALTER TABLE organisations
    ADD COLUMN deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN deletion_requested_by UUID REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN delete_after          TIMESTAMPTZ;

-- Support accounts: while an organisation allows Keston support access, the
-- Keston staff member who asked gets a temporary account in that
-- organisation (a global admin there), opened from their own account. It
-- has no usable password and stops working at expires_at.
ALTER TABLE users
    ADD COLUMN support_for UUID REFERENCES users (id) ON DELETE CASCADE,
    ADD COLUMN expires_at  TIMESTAMPTZ;
CREATE INDEX users_support_for ON users (support_for) WHERE support_for IS NOT NULL;
