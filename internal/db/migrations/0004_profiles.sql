-- Profile pictures, and which profile fields people may change themselves
-- (each organisation decides, in Keston Admin; admins can always change them).

ALTER TABLE users
    ADD COLUMN picture            BYTEA,
    ADD COLUMN picture_type       TEXT,
    ADD COLUMN picture_updated_at TIMESTAMPTZ;

-- {"name": bool, "email": bool, "picture": bool}. Missing = not allowed.
ALTER TABLE organisations ADD COLUMN profile_editing JSONB NOT NULL DEFAULT '{}';
