package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

func (s *Store) collectClients(rows pgx.Rows, err error) ([]Client, error) {
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Client, error) {
		c, err := scanClient(r)
		if err != nil {
			return Client{}, err
		}
		return *c, nil
	})
}

// BuiltinClients are Keston's own apps, which every organisation has.
func (s *Store) BuiltinClients(ctx context.Context) ([]Client, error) {
	return s.collectClients(s.DB.Query(ctx, `SELECT `+clientColumns+` FROM clients WHERE builtin ORDER BY name`))
}

// AllClients is every registered app, for admins choosing apps to add.
func (s *Store) AllClients(ctx context.Context) ([]Client, error) {
	return s.collectClients(s.DB.Query(ctx, `SELECT `+clientColumns+` FROM clients ORDER BY name`))
}

// OrganisationApp is an app an organisation has added for its people.
type OrganisationApp struct {
	Client  Client    `json:"client"`
	Mode    string    `json:"mode"` // "enabled" or "optional"
	AddedAt time.Time `json:"addedAt"`
}

func (s *Store) OrganisationApps(ctx context.Context, orgID string) ([]OrganisationApp, error) {
	rows, err := s.DB.Query(ctx, `SELECT oa.mode, oa.added_at, `+prefixed("c", clientColumns)+`
		FROM organisation_apps oa JOIN clients c ON c.id = oa.client_id
		WHERE oa.organisation_id = $1 ORDER BY c.name`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OrganisationApp, error) {
		var a OrganisationApp
		var c Client
		err := r.Scan(&a.Mode, &a.AddedAt, &c.ID, &c.Name, &c.Publisher, &c.Verification, &c.SecretHash,
			&c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.RequiredScopes, &c.OptionalScopes, &c.SkipConsent,
			&c.BackchannelLogoutURI, &c.PrivacyURL, &c.TermsURL, &c.DevMode, &c.Builtin)
		a.Client = c
		return a, err
	})
}

func (s *Store) SetOrganisationApp(ctx context.Context, orgID, clientID, mode string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO organisation_apps (organisation_id, client_id, mode) VALUES ($1, $2, $3)
		ON CONFLICT (organisation_id, client_id) DO UPDATE SET mode = $3`, orgID, clientID, mode)
	return err
}

func (s *Store) RemoveOrganisationApp(ctx context.Context, orgID, clientID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM organisation_apps WHERE organisation_id = $1 AND client_id = $2`,
		orgID, clientID)
	return err
}

// RemovedApps: optional organisation apps this person has removed.
func (s *Store) RemovedApps(ctx context.Context, userID string) (map[string]bool, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM removed_apps WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out, err
}

// RemoveAppForUser hides an optional organisation app and revokes its access.
func (s *Store) RemoveAppForUser(ctx context.Context, userID, clientID string) error {
	if _, err := s.DB.Exec(ctx, `INSERT INTO removed_apps (user_id, client_id) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, userID, clientID); err != nil {
		return err
	}
	return s.RevokeClient(ctx, userID, clientID)
}

// prefixed qualifies a column list with a table alias.
func prefixed(alias, columns string) string {
	out := ""
	for i, col := range splitColumns(columns) {
		if i > 0 {
			out += ", "
		}
		out += alias + "." + col
	}
	return out
}

func splitColumns(columns string) []string {
	var out []string
	cur := ""
	for _, r := range columns {
		switch r {
		case ',':
			out = append(out, cur)
			cur = ""
		case ' ', '\n', '\t':
		default:
			cur += string(r)
		}
	}
	return append(out, cur)
}
