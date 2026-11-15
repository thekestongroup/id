-- Deleted users: hidden and unable to sign in (status 'deleted'), kept for
-- 30 days so they can be restored with their groups, then removed for good
-- by housekeeping (store/deleted_users.go).
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'deleted'));

CREATE TABLE deleted_users (
    user_id         UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    deleted_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    -- Their status before, which restoring puts back.
    previous_status TEXT NOT NULL CHECK (previous_status IN ('active', 'disabled')),
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    purge_after     TIMESTAMPTZ NOT NULL
);
CREATE INDEX deleted_users_purge ON deleted_users (purge_after);
