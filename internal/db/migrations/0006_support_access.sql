-- Keston support access: platform admins (Keston staff) see the list of
-- organisations, but an organisation's accounts only while one of its
-- global admins has approved support access (for a limited time).
CREATE TABLE support_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users (id) ON DELETE SET NULL,
    reason          TEXT NOT NULL,
    -- pending → approved (until expires_at) or denied; revoked ends it early.
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'revoked')),
    -- 'request' (asked for, a global admin approves) or 'lockout' (granted
    -- after the lockout procedure, see below).
    via             TEXT NOT NULL DEFAULT 'request' CHECK (via IN ('request', 'lockout')),
    decided_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX support_requests_organisation ON support_requests (organisation_id, status);

-- Organisation lockout procedure: when nobody can get in, Keston staff
-- start it. Every global admin is notified, and unless one of them denies
-- it before effective_at (3 days), support access is granted, so Keston can
-- give someone their access back.
CREATE TABLE lockout_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users (id) ON DELETE SET NULL,
    reason          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'denied', 'completed', 'cancelled')),
    effective_at    TIMESTAMPTZ NOT NULL,
    decided_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX lockout_requests_organisation ON lockout_requests (organisation_id, status);

-- In-app notifications (Keston Admin's bell). Email comes later.
CREATE TABLE notifications (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type       TEXT NOT NULL DEFAULT 'info' CHECK (type IN ('info', 'success', 'warning', 'error')),
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    link       TEXT NOT NULL DEFAULT '',
    read_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user ON notifications (user_id, created_at DESC);
