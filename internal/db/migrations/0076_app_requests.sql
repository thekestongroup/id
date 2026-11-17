-- App requests: people ask their organisation's admins for an app they can't
-- use yet (Disabled for them, or a Keston product they have no licence for),
-- with a reason. Admins approve (adding them to the app's "Approved
-- requests" access rule and, if needed, assigning a licence) or decline.

CREATE TABLE app_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id  UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id        TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    reason           TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined', 'cancelled')),
    -- The admin's message to the requester (optional, on a decision).
    decision_message TEXT NOT NULL DEFAULT '',
    decided_by       UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_by_name  TEXT NOT NULL DEFAULT '',
    decided_at       TIMESTAMPTZ,
    -- What approving did.
    added_to_rule    BOOLEAN NOT NULL DEFAULT FALSE,
    licence_assigned BOOLEAN NOT NULL DEFAULT FALSE,
    -- The requester has seen the outcome.
    seen_at          TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- One pending request per person per app.
CREATE UNIQUE INDEX app_requests_one_pending ON app_requests (user_id, client_id) WHERE status = 'pending';
CREATE INDEX app_requests_organisation ON app_requests (organisation_id, status, created_at DESC);
CREATE INDEX app_requests_user ON app_requests (user_id, created_at DESC);

-- "Let people request apps" (Keston Admin → Apps). No row: on.
CREATE TABLE app_request_settings (
    organisation_id UUID PRIMARY KEY REFERENCES organisations (id) ON DELETE CASCADE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Apps people can't request (all others can, while requests are on).
CREATE TABLE app_request_exclusions (
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    PRIMARY KEY (organisation_id, client_id)
);

-- The access rule approvals add people to: one per app, kept first so it
-- wins over other rules, and recognised so it's reused.
ALTER TABLE app_rules ADD COLUMN approved_requests BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX app_rules_approved_requests ON app_rules (organisation_id, client_id) WHERE approved_requests;
