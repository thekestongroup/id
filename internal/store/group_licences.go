package store

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ── Group licences ───────────────────────────────────────────────────────
//
// A group can be given licences for Keston's products; every member then has
// them (see migration 0074 for the seat rule). Removing a licence from a
// group, or someone from a group, takes away only what came through it: a
// licence assigned to them directly stays.

// GroupLicences: the products a group gives its members.
func (s *Store) GroupLicences(ctx context.Context, groupID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM group_licences WHERE group_id = $1 ORDER BY client_id`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetGroupLicences makes a group's licences exactly these products (unknown
// IDs are ErrNotFound) and returns what was added and removed. It never
// fails for want of seats: members beyond the seats are "not licensed" (see
// GroupLicenceIssues) and no existing licence is taken away.
func (s *Store) SetGroupLicences(ctx context.Context, orgID, groupID string, by *string, products []string) (
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
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	if err := lockLicences(ctx, tx, orgID); err != nil {
		return nil, nil, err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT true FROM groups WHERE id = $1 AND organisation_id = $2`, groupID, orgID).
		Scan(&ok); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT client_id FROM group_licences WHERE group_id = $1`, groupID)
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
		if _, err := tx.Exec(ctx, `DELETE FROM group_licences WHERE group_id = $1 AND client_id = ANY($2)`,
			groupID, removed); err != nil {
			return nil, nil, err
		}
	}
	for _, p := range added {
		if _, err := tx.Exec(ctx, `INSERT INTO group_licences (group_id, client_id, assigned_by) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, groupID, p, by); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, tx.Commit(ctx)
}

// LicenceIssue: someone the group gives a licence to who has no seat for it.
type LicenceIssue struct {
	UserID   string   `json:"userId"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Products []string `json:"products"` // product IDs
}

// GroupLicenceIssues: the members of a group who have no seat for a product
// the group gives them, in the order they'd get one.
func (s *Store) GroupLicenceIssues(ctx context.Context, orgID, groupID string) ([]LicenceIssue, error) {
	rows, err := s.DB.Query(ctx, `SELECT u.id::text, u.name, u.email, array_agg(e.client_id ORDER BY e.client_id)
		FROM group_members m
		JOIN group_licences gl ON gl.group_id = m.group_id
		JOIN effective_licences e ON e.user_id = m.user_id AND e.client_id = gl.client_id AND e.organisation_id = $1
		JOIN users u ON u.id = m.user_id
		WHERE m.group_id = $2 AND NOT e.licensed
		GROUP BY u.id, u.name, u.email ORDER BY min(e.since), min(e.joined), u.id`, orgID, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LicenceIssue])
}

// UnlicensedSummary: how many people in the organisation have no seat for a
// licence a group gives them, and how many such licences, by product ID.
func (s *Store) UnlicensedSummary(ctx context.Context, orgID string) (people int, byProduct map[string]int, err error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id, count(*) FROM effective_licences
		WHERE organisation_id = $1 AND NOT licensed GROUP BY client_id`, orgID)
	if err != nil {
		return 0, nil, err
	}
	byProduct = map[string]int{}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return 0, nil, err
		}
		byProduct[id] = n
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	err = s.DB.QueryRow(ctx, `SELECT count(DISTINCT user_id) FROM effective_licences
		WHERE organisation_id = $1 AND NOT licensed`, orgID).Scan(&people)
	return people, byProduct, err
}
