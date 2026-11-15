-- Product licences: which of Keston's products (its built-in apps, e.g.
-- Keston Work) each user may use. No licence, no access, whatever the app
-- access settings say. No seat limits yet.
CREATE TABLE user_licences (
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by UUID REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX user_licences_client ON user_licences (client_id);

-- Nobody loses access: everyone gets a licence for each product today.
INSERT INTO user_licences (user_id, client_id)
SELECT u.id, c.id FROM users u CROSS JOIN clients c
WHERE c.builtin AND u.support_for IS NULL;
