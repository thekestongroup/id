-- Licence allocations: how many licences an organisation has for each of
-- Keston's products. seats NULL is unlimited; a number is a seat limit (0 is
-- allowed: nobody can be given one). Only TKG Admins change these. Lowering
-- seats below the licences in use is allowed (the organisation is then "over
-- allocation" and can't assign more until it's under).
-- No row means unlimited, so new organisations and new products start
-- unlimited too.
CREATE TABLE org_licences (
    organisation_id UUID NOT NULL REFERENCES organisations (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    seats           INTEGER CHECK (seats IS NULL OR seats >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      UUID REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (organisation_id, client_id)
);

-- Nothing breaks: every organisation gets unlimited licences for every
-- product it can use today.
INSERT INTO org_licences (organisation_id, client_id)
SELECT o.id, c.id FROM organisations o CROSS JOIN clients c WHERE c.builtin;
