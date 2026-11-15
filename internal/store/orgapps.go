package store

import (
	"context"

	"github.com/thekestongroup/id/internal/secret"
)

// ── Organisation apps ────────────────────────────────────────────────────
//
// Apps an organisation adds itself in Keston Admin (OpenID Connect or
// SAML). Only its users can sign in to them; they never get the claims or
// audiences of Keston's own apps (their verification is always "none").

// OrganisationClients: an organisation's own apps.
func (s *Store) OrganisationClients(ctx context.Context, orgID string) ([]Client, error) {
	return s.collectClients(s.DB.Query(ctx, `SELECT `+clientColumns+` FROM clients
		WHERE organisation_id = $1 ORDER BY lower(name)`, orgID))
}

// OrganisationClient: one of an organisation's own apps (ErrNotFound if it
// isn't one of theirs).
func (s *Store) OrganisationClient(ctx context.Context, orgID, clientID string) (*Client, error) {
	return scanClient(s.DB.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients
		WHERE organisation_id = $1 AND id = $2`, orgID, clientID))
}

// NewClientID: a random ID for an organisation's app.
func NewClientID() string { return secret.Token()[:22] }

// SaveOrganisationClient creates or updates an organisation's app. The
// secret is set separately (SetClientSecret). Keston-only settings
// (verification, builtin, skip consent, dev mode) are always off.
func (s *Store) SaveOrganisationClient(ctx context.Context, q Querier, orgID string, c *Client) error {
	var id string
	return q.QueryRow(ctx, `INSERT INTO clients (id, name, publisher, verification, redirect_uris,
			post_logout_redirect_uris, required_scopes, optional_scopes, privacy_url, terms_url, organisation_id,
			protocol, logo_url, native)
		VALUES ($1, $2, $3, 'none', $4, $5, $6, '{}', $7, $8, $9, $10, $11, $12)
		ON CONFLICT (id) DO UPDATE SET name = $2, publisher = $3, redirect_uris = $4,
			post_logout_redirect_uris = $5, required_scopes = $6, privacy_url = $7, terms_url = $8, logo_url = $11
		WHERE clients.organisation_id = $9
		RETURNING id`,
		c.ID, c.Name, c.Publisher, c.RedirectURIs, c.PostLogoutRedirectURIs, c.RequiredScopes, c.PrivacyURL,
		c.TermsURL, orgID, c.Protocol, c.LogoURL, c.Native).Scan(&id)
}

// SetClientSecret replaces an app's secret with a new one, returned once;
// only its hash is kept.
func (s *Store) SetClientSecret(ctx context.Context, orgID, clientID string) (string, error) {
	value := secret.Token()
	tag, err := s.DB.Exec(ctx, `UPDATE clients SET secret_hash = $3 WHERE organisation_id = $1 AND id = $2`,
		orgID, clientID, secret.HashPassword(value))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return value, nil
}

// DeleteOrganisationClient removes an organisation's app, with its access
// settings, grants and tokens.
func (s *Store) DeleteOrganisationClient(ctx context.Context, orgID, clientID string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM clients WHERE organisation_id = $1 AND id = $2`, orgID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
