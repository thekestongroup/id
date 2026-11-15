-- MFA for an organisation, as one setting (Keston Admin → Settings):
--   off       nobody has to use MFA
--   required  everyone, with a grace period to set it up (days, from when it
--             was turned on or when they joined, whichever is later)
--   custom    rules (today: per group, with mfa_required as the default for
--             everyone else; later also by app or network)
ALTER TABLE organisations
    ADD COLUMN mfa_mode TEXT NOT NULL DEFAULT 'required' CHECK (mfa_mode IN ('off', 'required', 'custom')),
    ADD COLUMN mfa_grace_days INT NOT NULL DEFAULT 7 CHECK (mfa_grace_days BETWEEN 0 AND 90),
    ADD COLUMN mfa_required_since TIMESTAMPTZ NOT NULL DEFAULT now();

-- Existing organisations keep what they had: group rules become custom
-- rules, and anyone already required to use MFA still is, straight away.
UPDATE organisations o SET
    mfa_mode = CASE
        WHEN EXISTS (SELECT 1 FROM groups g WHERE g.organisation_id = o.id AND g.mfa_required IS NOT NULL) THEN 'custom'
        WHEN o.mfa_required THEN 'required'
        ELSE 'off' END,
    mfa_grace_days = CASE WHEN o.mfa_required THEN 0 ELSE 7 END;

-- "Not now" during the grace period, for the rest of this session.
ALTER TABLE sessions ADD COLUMN mfa_skipped BOOLEAN NOT NULL DEFAULT FALSE;
