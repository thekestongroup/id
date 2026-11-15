-- Logs for Keston Admin (permission reports.view): what admins did, and
-- every sign-in attempt. Kept for a year (housekeeping deletes older rows).
--
-- Names and emails are copied in, and user IDs aren't foreign keys: support
-- accounts (and users) are deleted, but what they did stays in the log.

CREATE TABLE audit_log (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organisation_id    UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    -- Who did it. NULL: Keston ID itself (housekeeping).
    actor_id           UUID,
    actor_name         TEXT NOT NULL,
    actor_email        TEXT NOT NULL DEFAULT '',
    -- Through a Keston support account: the Keston staff member.
    support_staff_id   UUID,
    support_staff_name TEXT,
    -- e.g. user.password_reset (see store/logs.go).
    action             TEXT NOT NULL,
    -- What it was done to: user, group, app, organisation.
    target_type        TEXT NOT NULL DEFAULT '',
    target_id          TEXT,
    target_name        TEXT NOT NULL DEFAULT '',
    -- A short before → after, e.g. "Active → Disabled".
    summary            TEXT NOT NULL DEFAULT '',
    ip                 TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_organisation ON audit_log (organisation_id, id DESC);
CREATE INDEX audit_log_actor ON audit_log (actor_id, id DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_log_target ON audit_log (target_id, id DESC) WHERE target_id IS NOT NULL;
CREATE INDEX audit_log_created ON audit_log (created_at);

CREATE TABLE sign_in_log (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- The user's organisation; for an email nobody has, the organisation
    -- with its domain (NULL if none).
    organisation_id    UUID REFERENCES organisations (id) ON DELETE CASCADE,
    user_id            UUID,
    user_name          TEXT NOT NULL DEFAULT '',
    -- As typed, when nobody has it.
    email              TEXT NOT NULL DEFAULT '',
    -- password | mfa | backup_code | support | app
    method             TEXT NOT NULL,
    -- The app being signed in to (NULL: Keston ID itself).
    client_id          TEXT,
    success            BOOLEAN NOT NULL,
    -- Why it failed: wrong_password, unknown_user, locked, disabled…
    reason             TEXT NOT NULL DEFAULT '',
    -- A support sign-in: the Keston staff member.
    support_staff_id   UUID,
    support_staff_name TEXT,
    ip                 TEXT NOT NULL DEFAULT '',
    user_agent         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sign_in_log_organisation ON sign_in_log (organisation_id, id DESC);
CREATE INDEX sign_in_log_user ON sign_in_log (user_id, id DESC) WHERE user_id IS NOT NULL;
CREATE INDEX sign_in_log_created ON sign_in_log (created_at);
