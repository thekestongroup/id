-- Service health (incidents and scheduled maintenance) and the message
-- centre (announcements from Keston to organisations' admins).
--
-- Both are written by TKG Admins only and read by every organisation's
-- admins. Services are named by a fixed list in the code (store/health.go),
-- so no table for them.

CREATE TABLE service_incidents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    -- How badly the services are affected while it is open.
    impact      TEXT NOT NULL CHECK (impact IN ('degraded', 'outage')),
    status      TEXT NOT NULL DEFAULT 'investigating'
                CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
    services    TEXT[] NOT NULL,
    created_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);
CREATE INDEX service_incidents_open ON service_incidents (created_at DESC);

-- The timeline: every status change or note on an incident.
CREATE TABLE service_incident_updates (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id  UUID NOT NULL REFERENCES service_incidents (id) ON DELETE CASCADE,
    status       TEXT NOT NULL
                 CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
    message      TEXT NOT NULL,
    author_name  TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX service_incident_updates_incident ON service_incident_updates (incident_id, created_at);

CREATE TABLE maintenance_windows (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    services    TEXT[] NOT NULL,
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL CHECK (ends_at > starts_at),
    cancelled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE messages (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    -- A safe Markdown subset; Keston Admin renders it without raw HTML.
    body        TEXT NOT NULL,
    category    TEXT NOT NULL CHECK (category IN ('feature', 'change', 'action_required', 'notice')),
    action_by   DATE,
    -- Every organisation, or only the ones in organisation_ids.
    all_organisations BOOLEAN NOT NULL DEFAULT TRUE,
    organisation_ids  UUID[] NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    author_name TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX messages_created ON messages (created_at DESC);

-- Per admin: read and archived. No row means unread and not archived.
CREATE TABLE message_states (
    message_id  UUID NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    read_at     TIMESTAMPTZ,
    archived_at TIMESTAMPTZ,
    PRIMARY KEY (message_id, user_id)
);
