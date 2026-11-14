-- Which Keston ID browser session each app's tokens came from, so signing
-- out of Keston ID signs out of the apps too (their tokens are revoked, and
-- apps with a back-channel logout address are told).

ALTER TABLE access_tokens ADD COLUMN session_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN session_id TEXT;
CREATE INDEX access_tokens_session ON access_tokens (session_id);
CREATE INDEX refresh_tokens_session ON refresh_tokens (session_id);

-- Several accounts can be signed in to one browser. An app's sign-in asks
-- which to use (when more than one is signed in, or the app asks with
-- prompt=select_account), and records that the choice has been made.
ALTER TABLE auth_requests ADD COLUMN account_chosen BOOLEAN NOT NULL DEFAULT FALSE;
