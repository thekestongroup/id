-- Admin roles given straight to a user (Keston Admin → Add a user, or the
-- user's page), each a built-in set of permissions (store/roles.go). Global
-- admin stays users.role. Groups can still give permissions too.
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role    TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);
