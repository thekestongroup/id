-- Passkeys and security keys (WebAuthn). They count as MFA after a
-- password, and passkeys (discoverable credentials) also sign in on their
-- own, without a password.
CREATE TABLE passkeys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- The authenticator's credential ID, unique across every account.
    credential_id BYTEA NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    -- go-webauthn's Credential: public key, sign count, flags, AAGUID.
    credential    JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkeys_user_id ON passkeys (user_id);

-- A WebAuthn ceremony in progress (adding a passkey, or signing in with
-- one): the challenge and what it's for, kept on the server between the
-- two requests. Each is used once.
CREATE TABLE webauthn_ceremonies (
    -- Hash of the token the browser sends back.
    id         TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL CHECK (purpose IN ('register', 'mfa', 'sign-in')),
    -- Who it's for: the account adding a passkey, or the session at its MFA
    -- step. Neither for a passwordless sign-in.
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    session_id TEXT REFERENCES sessions (id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX webauthn_ceremonies_expires_at ON webauthn_ceremonies (expires_at);
