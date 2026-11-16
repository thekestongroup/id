-- TKG Admin (platform_admin) is now separate from Global Admin: only users
-- marked platform_admin in the platform organisation see every organisation.
-- Until now every global admin of The Keston Group counted, so mark them
-- all, and nobody loses access when this deploys.
UPDATE users SET platform_admin = TRUE
WHERE role = 'global_admin' AND NOT platform_admin
  AND organisation_id IN (SELECT id FROM organisations WHERE is_platform);
