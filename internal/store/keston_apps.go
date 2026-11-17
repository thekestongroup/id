package store

import (
	"context"

	"github.com/thekestongroup/id/internal/secret"
)

// ── Keston-wide apps ─────────────────────────────────────────────────────
//
// Apps every organisation sees (organisation_id NULL). Most are registered
// from deploy/clients.json (managed_by 'deployment', read-only in Keston
// Admin). TKG Admins also create, change and retire their own in Keston
// Admin (managed_by 'admin'): `keston-id clients sync` never overwrites
// those. They are never Keston products: no verification (so none of Keston's
// own claims or audiences), no licences, and the usual consent prompt.

// KestonPublisher publishes every Keston-wide app.
const KestonPublisher = "The Keston Group"

// KestonClients: every Keston-wide app, retired ones too.
func (s *Store) KestonClients(ctx context.Context) ([]Client, error) {
	return s.collectClients(s.DB.Query(ctx, `SELECT `+clientColumns+` FROM clients
		WHERE organisation_id IS NULL ORDER BY lower(name)`))
}

// KestonClient: one Keston-wide app (ErrNotFound if it isn't one).
func (s *Store) KestonClient(ctx context.Context, id string) (*Client, error) {
	return scanClient(s.DB.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients
		WHERE organisation_id IS NULL AND id = $1`, id))
}

// CreateKestonClient adds an admin-managed Keston-wide app.
func (s *Store) CreateKestonClient(ctx context.Context, c *Client) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, verification, redirect_uris,
			post_logout_redirect_uris, required_scopes, optional_scopes, privacy_url, terms_url, protocol, logo_url,
			native, description, managed_by)
		VALUES ($1, $2, $3, 'none', $4, $5, $6, '{}', $7, $8, 'oidc', $9, $10, $11, 'admin')`,
		c.ID, c.Name, KestonPublisher, c.RedirectURIs, c.PostLogoutRedirectURIs, c.RequiredScopes, c.PrivacyURL,
		c.TermsURL, c.LogoURL, c.Native, c.Description)
	return err
}

// UpdateKestonClient changes an admin-managed Keston-wide app (not its type).
func (s *Store) UpdateKestonClient(ctx context.Context, c *Client) error {
	tag, err := s.DB.Exec(ctx, `UPDATE clients SET name = $2, redirect_uris = $3, post_logout_redirect_uris = $4,
			required_scopes = $5, privacy_url = $6, terms_url = $7, logo_url = $8, description = $9
		WHERE id = $1 AND organisation_id IS NULL AND managed_by = 'admin'`,
		c.ID, c.Name, c.RedirectURIs, c.PostLogoutRedirectURIs, c.RequiredScopes, c.PrivacyURL, c.TermsURL,
		c.LogoURL, c.Description)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetKestonClientSecret replaces an admin-managed app's secret, returned
// once; only its hash is kept.
func (s *Store) SetKestonClientSecret(ctx context.Context, id string) (string, error) {
	value := secret.Token()
	tag, err := s.DB.Exec(ctx, `UPDATE clients SET secret_hash = $2
		WHERE id = $1 AND organisation_id IS NULL AND managed_by = 'admin'`, id, secret.HashPassword(value))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return value, nil
}

// RetireKestonClient retires an admin-managed app (no longer shown, and nobody
// can sign in to it), or brings it back.
func (s *Store) RetireKestonClient(ctx context.Context, id string, retire bool) error {
	tag, err := s.DB.Exec(ctx, `UPDATE clients SET retired_at = CASE WHEN $2 THEN coalesce(retired_at, now()) END
		WHERE id = $1 AND organisation_id IS NULL AND managed_by = 'admin'`, id, retire)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
