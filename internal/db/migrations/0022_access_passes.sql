-- Temporary access passes: a code an admin gives someone (e.g. after losing
-- their phone) to sign in with instead of their password and MFA. Then they
-- must set up MFA again. Only a hash of the code is kept.
CREATE TABLE access_passes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL UNIQUE,
    -- One-time: works once. Otherwise as often as needed until it expires.
    one_time     BOOLEAN NOT NULL,
    created_by   UUID REFERENCES users (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX access_passes_user ON access_passes (user_id);
