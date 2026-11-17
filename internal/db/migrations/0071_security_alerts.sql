-- Security alerts (Keston Admin → Security → Alerts) and the Secure Score.
--
-- An alert is raised for an organisation (an admin was added, MFA turned
-- off, many failed sign-ins…), listed on the Alerts page and delivered to
-- its global admins through the alert sinks (store/alerts.go): the in-app
-- notification bell today, email later. dedupe_key stops one burst of the
-- same thing raising an alert over and over.
CREATE TABLE security_alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    -- admin_added, admin_role_granted, mfa_off, password_policy_weakened,
    -- failed_sign_ins, account_locked, new_country.
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
    -- Who it's about (copied: it stays readable if they are deleted).
    subject_id      UUID,
    subject_name    TEXT NOT NULL DEFAULT '',
    -- Details for translating the alert in Keston Admin (country, count…).
    params          JSONB NOT NULL DEFAULT '{}',
    -- English text, for notifications and email.
    title           TEXT NOT NULL,
    body            TEXT NOT NULL DEFAULT '',
    dedupe_key      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_alerts_organisation ON security_alerts (organisation_id, created_at DESC);
CREATE INDEX security_alerts_dedupe ON security_alerts (organisation_id, dedupe_key, created_at DESC);

-- Countries each person has signed in from (Cloudflare's CF-IPCountry), to
-- spot a sign-in from somewhere new.
CREATE TABLE user_countries (
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    country    TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, country)
);

-- "Review the sign-in log": when a global admin last said they had.
ALTER TABLE organisations ADD COLUMN sign_in_log_reviewed_at TIMESTAMPTZ;
