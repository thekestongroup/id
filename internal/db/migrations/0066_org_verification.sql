-- Organisation verification. An organisation can only be used (its people
-- can only sign in) once it's verified. Organisations made while
-- "Require verification for new organisations" is on, through the public
-- sign-up, start unverified until Keston staff verify them.
ALTER TABLE organisations
    ADD COLUMN verified_at TIMESTAMPTZ,
    ADD COLUMN verified_by UUID REFERENCES users (id) ON DELETE SET NULL;

-- Everything that exists now is verified, the platform organisation included.
UPDATE organisations SET verified_at = created_at;

-- The platform organisation can never be unverified.
ALTER TABLE organisations
    ADD CONSTRAINT organisations_platform_verified CHECK (NOT is_platform OR verified_at IS NOT NULL);

-- Platform-wide settings: one row, changed by platform admins only.
CREATE TABLE platform_settings (
    singleton                       BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    require_organisation_verification BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO platform_settings (singleton) VALUES (TRUE);
