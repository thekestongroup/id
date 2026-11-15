package store

import (
	"context"

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

// ClientsFor is every app an organisation can use: those Keston registered,
// and its own (never another organisation's).
func (s *Store) ClientsFor(ctx context.Context, orgID string) ([]Client, error) {
	return s.collectClients(s.DB.Query(ctx, `SELECT `+clientColumns+` FROM clients
		WHERE organisation_id IS NULL OR organisation_id = $1 ORDER BY name`, orgID))
}

// RemovedApps: apps this person has turned off (where they're allowed to).
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

// RemoveAppForUser turns an app off for this person, and revokes its access.
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
