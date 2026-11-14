-- Keston ID schema. Every replica is stateless: all state lives here, so
-- any number of containers can sit behind the load balancer.

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL,
    name                TEXT NOT NULL,
    organisation        TEXT NOT NULL DEFAULT '',
    password_hash       TEXT NOT NULL,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Authenticator app (TOTP) secret, encrypted. Set but not enabled while
    -- someone is still setting it up.
    totp_secret         BYTEA,
    totp_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    -- Hashes of one-time backup codes.
    backup_codes        TEXT[] NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    failed_logins       INT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email ON users (lower(email));

-- Apps registered with Keston ID (OAuth clients).
CREATE TABLE clients (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    publisher                 TEXT NOT NULL,
    verification              TEXT NOT NULL DEFAULT 'none' CHECK (verification IN ('owned', 'verified', 'none')),
    -- NULL for public clients (SPAs, mobile), which must use PKCE.
    secret_hash               TEXT,
    redirect_uris             TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    -- Scopes it can't work without, and those people may untick.
    required_scopes           TEXT[] NOT NULL DEFAULT '{openid}',
    optional_scopes           TEXT[] NOT NULL DEFAULT '{}',
    -- Skip the consent prompt (The Keston Group's own apps can opt in).
    skip_consent              BOOLEAN NOT NULL DEFAULT FALSE,
    backchannel_logout_uri    TEXT NOT NULL DEFAULT '',
    privacy_url               TEXT NOT NULL DEFAULT '',
    terms_url                 TEXT NOT NULL DEFAULT '',
    dev_mode                  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Browser sessions on Keston ID itself. The cookie holds a random token;
-- only its hash is stored.
CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- 'password': first step done; 'verified': fully signed in.
    stage        TEXT NOT NULL CHECK (stage IN ('password', 'verified')),
    amr          TEXT[] NOT NULL DEFAULT '{}',
    auth_time    TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent   TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- An app asking for access, from /authorize until the code is exchanged.
CREATE TABLE auth_requests (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id             TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL,
    scopes                TEXT[] NOT NULL,
    state                 TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    response_type         TEXT NOT NULL,
    response_mode         TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    prompt                TEXT[] NOT NULL DEFAULT '{}',
    max_age_seconds       INT,
    login_hint            TEXT NOT NULL DEFAULT '',
    -- Filled in once someone signs in and allows it.
    user_id               UUID REFERENCES users (id) ON DELETE CASCADE,
    session_id            TEXT,
    auth_time             TIMESTAMPTZ,
    amr                   TEXT[] NOT NULL DEFAULT '{}',
    done                  BOOLEAN NOT NULL DEFAULT FALSE,
    code_hash             TEXT UNIQUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL
);
CREATE INDEX auth_requests_expires ON auth_requests (expires_at);

-- What someone has allowed each app.
CREATE TABLE grants (
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    scopes     TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);

-- Refresh tokens rotate on every use; only hashes are stored.
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    client_id  TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    audience   TEXT[] NOT NULL,
    scopes     TEXT[] NOT NULL,
    amr        TEXT[] NOT NULL DEFAULT '{}',
    auth_time  TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX refresh_tokens_user_client ON refresh_tokens (user_id, client_id);

-- Access tokens are signed JWTs that apps can check on their own; this row
-- lets Keston ID revoke one before it expires (userinfo, introspection).
CREATE TABLE access_tokens (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id        TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id          UUID REFERENCES users (id) ON DELETE CASCADE,
    audience         TEXT[] NOT NULL,
    scopes           TEXT[] NOT NULL,
    refresh_token_id UUID REFERENCES refresh_tokens (id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL
);
CREATE INDEX access_tokens_user_client ON access_tokens (user_id, client_id);
CREATE INDEX access_tokens_expires ON access_tokens (expires_at);

-- Token signing keys (RS256). Private keys are encrypted with
-- KESTON_ID_SECRET_KEY. Old keys stay published until tokens signed with
-- them have expired.
CREATE TABLE signing_keys (
    id          TEXT PRIMARY KEY,
    algorithm   TEXT NOT NULL,
    private_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);
