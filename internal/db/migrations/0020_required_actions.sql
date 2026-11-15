-- Required actions: things someone must do during sign-in, after their
-- password (and MFA) and before any app gets tokens: choose a new password,
-- set up MFA. A session in the new 'actions' stage has signed in but isn't
-- fully verified until they're done.
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_stage_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_stage_check CHECK (stage IN ('password', 'actions', 'verified'));

-- Set by an admin (new user, password reset, or "Require password change"):
-- they choose a new password next time they sign in.
ALTER TABLE users ADD COLUMN password_change_required BOOLEAN NOT NULL DEFAULT FALSE;

-- An authenticator being set up during sign-in, kept apart from the one in
-- use (totp_secret) until it's confirmed, so starting again with an access
-- pass doesn't turn off MFA that still works.
ALTER TABLE users ADD COLUMN totp_pending BYTEA;
