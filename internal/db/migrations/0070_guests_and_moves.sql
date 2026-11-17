-- Guests and account moves.
--
-- An account always belongs to one home organisation (users.organisation_id):
-- its email is username@home-domain, and apps, tokens and sign-in only ever
-- use it. A guest membership lets someone from another organisation work in
-- Keston Admin as a member of this one, with whatever groups and admin roles
-- this organisation gives them there. Only the home organisation's own
-- people are ever "members" for sign-in purposes.

-- "Allow users to be guests in other organisations" (Security). Off until a
-- global admin turns it on: invitations never reach people whose home
-- organisation hasn't.
ALTER TABLE organisations ADD COLUMN allow_guests BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE guest_memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The organisation they're a guest in (not their home one).
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Their role there: a guest is always a member (never a global admin);
    -- the admin roles below and their groups there give them anything more.
    role            TEXT NOT NULL DEFAULT 'member' CHECK (role = 'member'),
    admin_roles     TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'declined', 'removed')),
    invited_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    invited_by_name TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at    TIMESTAMPTZ
);
-- One row per person per organisation: a new invitation after declining or
-- being removed reuses it (the audit log keeps the history).
CREATE UNIQUE INDEX guest_memberships_one ON guest_memberships (organisation_id, user_id);
CREATE INDEX guest_memberships_user ON guest_memberships (user_id, status);

-- Moving an account to another home organisation: asked for by a global admin
-- of the current one, accepted or declined by a global admin of the other.
CREATE TABLE account_moves (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    from_organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    to_organisation_id   UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    old_email            TEXT NOT NULL,
    new_email            TEXT NOT NULL,
    user_name            TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled')),
    requested_by         UUID REFERENCES users (id) ON DELETE SET NULL,
    requested_by_name    TEXT NOT NULL DEFAULT '',
    decided_by           UUID REFERENCES users (id) ON DELETE SET NULL,
    decided_by_name      TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at           TIMESTAMPTZ,
    CHECK (from_organisation_id <> to_organisation_id)
);
CREATE UNIQUE INDEX account_moves_pending ON account_moves (user_id) WHERE status = 'pending';
CREATE INDEX account_moves_to ON account_moves (to_organisation_id, status);
CREATE INDEX account_moves_from ON account_moves (from_organisation_id, status);

-- Which one-time pop-ups someone has already seen (an invitation or a move
-- request, by kind and ID), so each appears once.
CREATE TABLE prompt_seen (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,
    ref_id  UUID NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, kind, ref_id)
);
