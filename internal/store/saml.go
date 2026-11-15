package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── SAML apps ────────────────────────────────────────────────────────────
//
// A SAML app is a client (protocol "saml", owned by an organisation) plus
// its service provider details here.

type SAMLApp struct {
	ClientID    string    `json:"clientId"`
	EntityID    string    `json:"entityId"`
	MetadataURL string    `json:"metadataUrl"`
	Metadata    string    `json:"-"`
	ACSURL      string    `json:"acsUrl"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

const samlAppColumns = `client_id, entity_id, metadata_url, metadata, acs_url, updated_at`

func scanSAMLApp(row pgx.Row) (*SAMLApp, error) {
	var a SAMLApp
	if err := row.Scan(&a.ClientID, &a.EntityID, &a.MetadataURL, &a.Metadata, &a.ACSURL, &a.UpdatedAt); err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) SAMLApp(ctx context.Context, clientID string) (*SAMLApp, error) {
	return scanSAMLApp(s.DB.QueryRow(ctx, `SELECT `+samlAppColumns+` FROM saml_apps WHERE client_id = $1`, clientID))
}

// SAMLAppByEntityID: an organisation's SAML app with this entity ID.
func (s *Store) SAMLAppByEntityID(ctx context.Context, orgID, entityID string) (*SAMLApp, error) {
	return scanSAMLApp(s.DB.QueryRow(ctx, `SELECT `+prefixed("s", samlAppColumns)+` FROM saml_apps s
		JOIN clients c ON c.id = s.client_id WHERE c.organisation_id = $1 AND s.entity_id = $2`, orgID, entityID))
}

// SaveSAMLApp creates or updates a SAML app: its client row and its
// service provider details, together.
func (s *Store) SaveSAMLApp(ctx context.Context, orgID string, c *Client, app *SAMLApp) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	c.Protocol = "saml"
	c.RedirectURIs = []string{app.ACSURL}
	c.PostLogoutRedirectURIs = []string{}
	c.RequiredScopes = []string{"openid"}
	if err := s.SaveOrganisationClient(ctx, tx, orgID, c); err != nil {
		return notFound(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO saml_apps (client_id, entity_id, metadata_url, metadata, acs_url)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (client_id) DO UPDATE SET entity_id = $2, metadata_url = $3, metadata = $4, acs_url = $5,
			updated_at = now()`, c.ID, app.EntityID, app.MetadataURL, app.Metadata, app.ACSURL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ── SAML signing certificate ─────────────────────────────────────────────

type SAMLCertificate struct {
	ID          string
	Certificate []byte // DER
	PrivateKey  []byte // encrypted PKCS#8
	CreatedAt   time.Time
}

// SAMLCertificate: the active one (ErrNotFound if none yet).
func (s *Store) SAMLCertificate(ctx context.Context) (*SAMLCertificate, error) {
	var c SAMLCertificate
	err := s.DB.QueryRow(ctx, `SELECT id, certificate, private_key, created_at FROM saml_certificates
		WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1`).Scan(&c.ID, &c.Certificate, &c.PrivateKey,
		&c.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

func (s *Store) AddSAMLCertificate(ctx context.Context, c *SAMLCertificate) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO saml_certificates (id, certificate, private_key) VALUES ($1, $2, $3)`,
		c.ID, c.Certificate, c.PrivateKey)
	return err
}

// ── SAML sign-ins ────────────────────────────────────────────────────────

// CreateSAMLAuthRequest records a SAML sign-in waiting for someone to sign
// in: request is the query string or form it arrived with ("" when Keston
// ID starts it), acsURL where the response goes, relayState the app's.
func (s *Store) CreateSAMLAuthRequest(ctx context.Context, clientID, binding, request, acsURL, relayState string,
	forceAuthn bool, ttl time.Duration) (*AuthRequest, error) {
	prompt := []string{}
	if forceAuthn {
		prompt = []string{"login"}
	}
	return scanAuthRequest(s.DB.QueryRow(ctx, `INSERT INTO auth_requests (client_id, redirect_uri, scopes, state,
			response_type, response_mode, prompt, saml_request, expires_at)
		VALUES ($1, $2, '{openid}', $3, 'saml', $4, $5, $6, now() + $7::interval)
		RETURNING `+authRequestColumns, clientID, acsURL, relayState, binding, prompt, request, ttl))
}

// SAMLRequest: the original request of a SAML sign-in.
func (s *Store) SAMLRequest(ctx context.Context, authRequestID string) (string, error) {
	var req string
	err := s.DB.QueryRow(ctx, `SELECT saml_request FROM auth_requests WHERE id = $1`, authRequestID).Scan(&req)
	return req, notFound(err)
}

// GroupNamesForUser: the names of the groups someone is in.
func (s *Store) GroupNamesForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT g.name FROM groups g JOIN group_members m ON m.group_id = g.id
		WHERE m.user_id = $1 ORDER BY lower(g.name)`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
