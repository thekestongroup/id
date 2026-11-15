package store

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ── Product licences ─────────────────────────────────────────────────────
//
// Keston's products are its built-in apps (e.g. Keston Work). Someone can
// use a product only with a licence for it, assigned in Keston Admin; the
// app access settings (Forced, Enabled, Disabled) then apply on top. There
// are no seat limits yet. Support accounts don't need licences.

// Product: one of Keston's products, and how many of an organisation's
// users have a licence for it.
type Product struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	Assigned  int    `json:"assigned"`
}

func (s *Store) Products(ctx context.Context, orgID string) ([]Product, error) {
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.name, c.publisher,
		(SELECT count(*) FROM user_licences l JOIN users u ON u.id = l.user_id
		 WHERE l.client_id = c.id AND u.organisation_id = $1 AND u.status <> 'deleted')
		FROM clients c WHERE c.builtin ORDER BY c.name`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Product, error) {
		var p Product
		err := r.Scan(&p.ID, &p.Name, &p.Publisher, &p.Assigned)
		return p, err
	})
}

// Licences: the products someone has a licence for.
func (s *Store) Licences(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM user_licences WHERE user_id = $1 ORDER BY client_id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// LicencesInOrganisation: everyone's licences, by user ID.
func (s *Store) LicencesInOrganisation(ctx context.Context, orgID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT l.user_id, l.client_id FROM user_licences l
		JOIN users u ON u.id = l.user_id WHERE u.organisation_id = $1 ORDER BY l.client_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var user, client string
		if err := rows.Scan(&user, &client); err != nil {
			return nil, err
		}
		out[user] = append(out[user], client)
	}
	return out, rows.Err()
}

// SetLicences makes someone's licences exactly these products (unknown IDs
// are ErrNotFound). It returns what was added and removed.
func (s *Store) SetLicences(ctx context.Context, userID string, by *string, products []string) (
	added, removed []string, err error) {
	known, err := s.ProductIDs(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range products {
		if !slices.Contains(known, p) {
			return nil, nil, ErrNotFound
		}
	}
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM user_licences WHERE user_id = $1`, userID)
	if err != nil {
		return nil, nil, err
	}
	before, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, nil, err
	}
	for _, p := range products {
		if !slices.Contains(before, p) && !slices.Contains(added, p) {
			added = append(added, p)
		}
	}
	for _, p := range before {
		if !slices.Contains(products, p) {
			removed = append(removed, p)
		}
	}
	if len(removed) > 0 {
		if _, err := s.DB.Exec(ctx, `DELETE FROM user_licences WHERE user_id = $1 AND client_id = ANY($2)`,
			userID, removed); err != nil {
			return nil, nil, err
		}
	}
	for _, p := range added {
		if _, err := s.DB.Exec(ctx, `INSERT INTO user_licences (user_id, client_id, assigned_by) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, userID, p, by); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, nil
}

// Licensed: whether someone may use this app as far as licences go (always,
// for apps that aren't Keston products, and for support accounts).
func (s *Store) Licensed(ctx context.Context, u *User, clientID string) (bool, error) {
	if u.IsSupport() {
		return true, nil
	}
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM clients WHERE id = $2 AND builtin)
		OR EXISTS (SELECT 1 FROM user_licences WHERE user_id = $1 AND client_id = $2)`, u.ID, clientID).Scan(&ok)
	return ok, err
}

// ProductIDs: the IDs of Keston's products.
func (s *Store) ProductIDs(ctx context.Context) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT id FROM clients WHERE builtin ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
