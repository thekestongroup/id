-- Group licences: a licence for a product can be given to a group, and then
-- every member has it. Someone can hold a licence directly (user_licences),
-- through groups (group_licences + group_members), or both; either way it
-- takes one seat.
--
-- Seat rule: the organisation's seats (org_licences) are shared by everyone
-- who holds the licence. Direct licences always keep their seat (nothing is
-- ever taken away because seats ran short). People who only have it through
-- a group fill the seats that are left, in order of when they got the licence
-- through a group (the later of joining the group and the group being given
-- the licence), then when they joined, then user ID, so the order is stable
-- and giving a group a licence never bumps someone who already has one; anyone past the last
-- seat is "not licensed: no seats left" until a seat frees up or seats are
-- added. Groups can always be given licences and members added.
CREATE TABLE group_licences (
    group_id    UUID NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by UUID REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, client_id)
);
CREATE INDEX group_licences_client ON group_licences (client_id);

-- Everyone who holds (or would hold) a licence, once per user and product:
-- direct (assigned to them), since (when they got it), and licensed (they have
-- a seat). Deleted users and support accounts are left out. Filter by
-- organisation_id first (it's what the seat order is worked out within).
CREATE VIEW effective_licences AS
SELECT x.user_id, x.client_id, x.organisation_id, x.direct, x.since, x.joined,
       (x.direct OR o.seats IS NULL OR x.grank <= greatest(o.seats - x.directs, 0)) AS licensed
FROM (
    SELECT a.*,
           count(*) FILTER (WHERE a.direct) OVER (PARTITION BY a.organisation_id, a.client_id) AS directs,
           row_number() OVER (PARTITION BY a.organisation_id, a.client_id, a.direct
                              ORDER BY a.since, a.joined, a.user_id) AS grank
    FROM (
        SELECT s.user_id, s.client_id, u.organisation_id, bool_or(s.direct) AS direct, min(s.since) AS since, min(s.joined) AS joined
        FROM (
            SELECT l.user_id, l.client_id, true AS direct, l.assigned_at AS since, l.assigned_at AS joined FROM user_licences l
            UNION ALL
            SELECT m.user_id, gl.client_id, false, greatest(m.added_at, gl.assigned_at), m.added_at
            FROM group_members m
            JOIN group_licences gl ON gl.group_id = m.group_id
            JOIN groups g ON g.id = m.group_id
            JOIN users gu ON gu.id = m.user_id
            WHERE g.organisation_id = gu.organisation_id
        ) s
        JOIN users u ON u.id = s.user_id
        WHERE u.status <> 'deleted' AND u.support_for IS NULL
        GROUP BY s.user_id, s.client_id, u.organisation_id
    ) a
) x
LEFT JOIN org_licences o ON o.organisation_id = x.organisation_id AND o.client_id = x.client_id;
