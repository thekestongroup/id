CREATE TABLE IF NOT EXISTS clients (
    id                     TEXT PRIMARY KEY,
    secret                 TEXT NOT NULL DEFAULT '',
    redirect_uris          TEXT NOT NULL DEFAULT '[]',
    grant_types            TEXT NOT NULL DEFAULT '[]',
    response_types         TEXT NOT NULL DEFAULT '[]',
    scopes                 TEXT NOT NULL DEFAULT '[]',
    audience               TEXT NOT NULL DEFAULT '[]',
    public                 BOOLEAN NOT NULL DEFAULT FALSE,
    backchannel_logout_uri TEXT NOT NULL DEFAULT ''
);

ALTER TABLE clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active'
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS authorize_codes (
    code    TEXT PRIMARY KEY,
    request TEXT NOT NULL,
    active  BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    signature  TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    request    TEXT NOT NULL,
    active     BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    authorize_code TEXT PRIMARY KEY,
    request        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pkce_sessions (
    signature TEXT PRIMARY KEY,
    request   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_assertion_jti (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_sessions (
    sid        TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_request_id ON refresh_tokens (request_id);
