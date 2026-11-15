-- Keston Admin permissions, given to groups (e.g. "Support team" can reset
-- passwords). See store/permissions.go for the list.
CREATE TABLE group_permissions (
    group_id   UUID NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (group_id, permission)
);
