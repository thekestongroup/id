-- Require MFA: the organisation's default, overridden per group (NULL: use
-- the default). If any of someone's groups requires it, it's required;
-- otherwise a group that doesn't require it wins over the default.
ALTER TABLE organisations ADD COLUMN mfa_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE groups ADD COLUMN mfa_required BOOLEAN;
