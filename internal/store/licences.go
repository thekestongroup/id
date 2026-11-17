package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ── Product licences ─────────────────────────────────────────────────────
//
// Keston's products are its built-in apps (e.g. Keston Work). Someone can
// use a product only with a licence for it, assigned in Keston Admin; the
// app access settings (Forced, Enabled, Disabled) then apply on top. There
// are no seat limits yet. Support accounts don't need licences.

// Product: one of Keston's products, how many of an organisation's users
// have a licence for it, and how many licences the organisation has.
type Product struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
	// Assigned (also Used): licences in use.
	Assigned int `json:"assigned"`
	// Seats: the licences the organisation has; nil is unlimited.
	Seats *int `json:"seats"`
	// Unlimited: Seats is nil.
	Unlimited bool `json:"unlimited"`
	// Available: seats left (nil when unlimited; 0 when full or over).
	Available *int `json:"available"`
	// OverAllocated: more in use than seats, so nothing more can be assigned.
	OverAllocated bool `json:"overAllocated"`
	// Direct: licences assigned straight to people (Assigned also counts
	// those who only have it through a group, once, whichever way).
	// Unlicensed: people a group gives it to who have no seat left.
	Unlicensed int `json:"unlicensed"`
	// Groups: the groups that give this licence to their members.
	Groups []GroupRef `json:"groups"`
}

// GroupRef: a group, by ID and name.
type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (p *Product) fill() {
	p.Unlimited = p.Seats == nil
	p.Available, p.OverAllocated = nil, false
	if p.Seats != nil {
		left := max(*p.Seats-p.Assigned, 0)
		p.Available = &left
		p.OverAllocated = p.Assigned > *p.Seats
	}
}

// NoSeatsError: assigning would go past an organisation's licences.
type NoSeatsError struct {
	Products []string // IDs
	Names    []string
	Over     bool // already over allocation (rather than just full)
}

func (e *NoSeatsError) Error() string {
	return "no licences left for " + strings.Join(e.Names, ", ")
}

// ErrNoSeats: errors.Is(err, ErrNoSeats) for a *NoSeatsError.
var ErrNoSeats = errors.New("no licences left")

func (e *NoSeatsError) Is(target error) bool { return target == ErrNoSeats }

func (s *Store) Products(ctx context.Context, orgID string) ([]Product, error) {
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.name, c.publisher,
		(SELECT count(*) FROM effective_licences e WHERE e.organisation_id = $1 AND e.client_id = c.id AND e.licensed),
		(SELECT o.seats FROM org_licences o WHERE o.organisation_id = $1 AND o.client_id = c.id),
		(SELECT count(*) FROM effective_licences e WHERE e.organisation_id = $1 AND e.client_id = c.id AND NOT e.licensed)
		FROM clients c WHERE c.builtin ORDER BY c.name`, orgID)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Product, error) {
		var p Product
		err := r.Scan(&p.ID, &p.Name, &p.Publisher, &p.Assigned, &p.Seats, &p.Unlicensed)
		p.fill()
		p.Groups = []GroupRef{}
		return p, err
	})
	if err != nil {
		return nil, err
	}
	grows, err := s.DB.Query(ctx, `SELECT gl.client_id, g.id::text, g.name FROM group_licences gl
		JOIN groups g ON g.id = gl.group_id WHERE g.organisation_id = $1 ORDER BY lower(g.name)`, orgID)
	if err != nil {
		return nil, err
	}
	defer grows.Close()
	for grows.Next() {
		var client string
		var g GroupRef
		if err := grows.Scan(&client, &g.ID, &g.Name); err != nil {
			return nil, err
		}
		for i := range list {
			if list[i].ID == client {
				list[i].Groups = append(list[i].Groups, g)
			}
		}
	}
	return list, grows.Err()
}

// Licences: the products someone has a licence for and a seat in: assigned
// to them or through a group (effective_licences).
func (s *Store) Licences(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT e.client_id FROM effective_licences e
		WHERE e.organisation_id = (SELECT organisation_id FROM users WHERE id = $1)
		AND e.user_id = $1 AND e.licensed ORDER BY e.client_id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// DirectLicences: only the products assigned to someone themselves (what
// Manage licences changes), not those through groups.
func (s *Store) DirectLicences(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM user_licences WHERE user_id = $1 ORDER BY client_id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// LicenceSource: where someone's licence for a product comes from.
type LicenceSource struct {
	Product string `json:"product"`
	Name    string `json:"name"`
	// Direct: assigned to them. Groups: the groups that give it to them.
	Direct bool       `json:"direct"`
	Groups []GroupRef `json:"groups"`
	// Licensed: they have a seat. False only for a licence through groups
	// when the organisation has no seats left ("Not licensed: no seats left").
	Licensed bool `json:"licensed"`
}

// LicenceSources: every licence someone holds or is given through groups,
// and whether each has a seat.
func (s *Store) LicenceSources(ctx context.Context, userID string) ([]LicenceSource, error) {
	rows, err := s.DB.Query(ctx, `SELECT e.client_id, c.name, e.direct, e.licensed,
		coalesce((SELECT json_agg(json_build_object('id', g.id, 'name', g.name) ORDER BY lower(g.name))
			FROM group_members m JOIN group_licences gl ON gl.group_id = m.group_id
			JOIN groups g ON g.id = m.group_id
			WHERE m.user_id = $1 AND gl.client_id = e.client_id AND g.organisation_id = e.organisation_id), '[]'::json)
		FROM effective_licences e JOIN clients c ON c.id = e.client_id
		WHERE e.organisation_id = (SELECT organisation_id FROM users WHERE id = $1) AND e.user_id = $1
		ORDER BY c.name`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (LicenceSource, error) {
		var l LicenceSource
		err := r.Scan(&l.Product, &l.Name, &l.Direct, &l.Licensed, &l.Groups)
		if l.Groups == nil {
			l.Groups = []GroupRef{}
		}
		return l, err
	})
}

// LicencesInOrganisation: everyone's licences (with a seat), by user ID.
func (s *Store) LicencesInOrganisation(ctx context.Context, orgID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT e.user_id, e.client_id FROM effective_licences e
		WHERE e.organisation_id = $1 AND e.licensed ORDER BY e.client_id`, orgID)
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

// UnlicensedProducts: the names of the products a group gives someone but
// they have no seat for.
func (s *Store) UnlicensedProducts(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT c.name FROM effective_licences e JOIN clients c ON c.id = e.client_id
		WHERE e.organisation_id = (SELECT organisation_id FROM users WHERE id = $1)
		AND e.user_id = $1 AND NOT e.licensed ORDER BY c.name`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetLicences makes someone's licences exactly these products (unknown IDs
// are ErrNotFound). It returns what was added and removed. Adding one the
// organisation has no seats left for fails with a *NoSeatsError (nothing
// changes); taking licences away is always allowed.
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
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	var orgID string
	if err := tx.QueryRow(ctx, `SELECT organisation_id FROM users WHERE id = $1`, userID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	if err := lockLicences(ctx, tx, orgID); err != nil {
		return nil, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT client_id FROM user_licences WHERE user_id = $1`, userID)
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
	// A licence they already have a seat for through a group needs no new one.
	var needSeat []string
	for _, p := range added {
		var has bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM effective_licences
			WHERE organisation_id = $1 AND user_id = $2 AND client_id = $3 AND licensed)`,
			orgID, userID, p).Scan(&has); err != nil {
			return nil, nil, err
		}
		if !has {
			needSeat = append(needSeat, p)
		}
	}
	if err := checkSeats(ctx, tx, orgID, needSeat, 1); err != nil {
		return nil, nil, err
	}
	if len(removed) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM user_licences WHERE user_id = $1 AND client_id = ANY($2)`,
			userID, removed); err != nil {
			return nil, nil, err
		}
	}
	for _, p := range added {
		if _, err := tx.Exec(ctx, `INSERT INTO user_licences (user_id, client_id, assigned_by) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, userID, p, by); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, tx.Commit(ctx)
}

// lockLicences serialises licence changes in an organisation until the
// transaction ends, so two requests can't both take the last seat.
func lockLicences(ctx context.Context, tx pgx.Tx, orgID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "licences:"+orgID)
	return err
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// checkSeats: whether n more users can have each of these products. It
// returns a *NoSeatsError for those they can't (full, or over allocation).
func checkSeats(ctx context.Context, q queryRower, orgID string, products []string, n int) error {
	var e NoSeatsError
	for _, p := range products {
		var name string
		var seats *int
		var used int
		if err := q.QueryRow(ctx, `SELECT c.name,
			(SELECT o.seats FROM org_licences o WHERE o.organisation_id = $1 AND o.client_id = c.id),
			(SELECT count(*) FROM effective_licences e
			 WHERE e.client_id = c.id AND e.organisation_id = $1 AND e.licensed)
			FROM clients c WHERE c.id = $2`, orgID, p).Scan(&name, &seats, &used); err != nil {
			return err
		}
		if seats != nil && used+n > *seats {
			e.Products = append(e.Products, p)
			e.Names = append(e.Names, name)
			e.Over = e.Over || used > *seats
		}
	}
	if len(e.Products) > 0 {
		return &e
	}
	return nil
}

// CheckSeats: whether an organisation has seats for n more users to have
// each of these products (a *NoSeatsError if not). It's a check before
// creating someone; SetLicences enforces it again when it assigns.
func (s *Store) CheckSeats(ctx context.Context, orgID string, products []string, n int) error {
	return checkSeats(ctx, s.DB, orgID, products, n)
}

// SetAllocations sets how many licences an organisation has: seats per
// product ID (nil is unlimited). Unknown products are ErrNotFound. It
// returns a summary of what changed ("" if nothing).
func (s *Store) SetAllocations(ctx context.Context, orgID string, by *string, seats map[string]*int) (string, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if err := lockLicences(ctx, tx, orgID); err != nil {
		return "", err
	}
	rows, err := tx.Query(ctx, `SELECT c.id, c.name, o.seats FROM clients c
		LEFT JOIN org_licences o ON o.client_id = c.id AND o.organisation_id = $1
		WHERE c.builtin ORDER BY c.name`, orgID)
	if err != nil {
		return "", err
	}
	type cur struct {
		id, name string
		seats    *int
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cur, error) {
		var c cur
		return c, r.Scan(&c.id, &c.name, &c.seats)
	})
	if err != nil {
		return "", err
	}
	label := func(n *int) string {
		if n == nil {
			return "unlimited"
		}
		return fmt.Sprint(*n)
	}
	var parts []string
	for id := range seats {
		if !slices.ContainsFunc(list, func(c cur) bool { return c.id == id }) {
			return "", ErrNotFound
		}
	}
	for _, c := range list {
		n, ok := seats[c.id]
		if !ok {
			continue
		}
		if (n == nil) != (c.seats == nil) || (n != nil && *n != *c.seats) {
			parts = append(parts, c.name+": "+label(c.seats)+" → "+label(n))
		}
		if _, err := tx.Exec(ctx, `INSERT INTO org_licences (organisation_id, client_id, seats, updated_by)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (organisation_id, client_id) DO UPDATE SET seats = $3, updated_by = $4, updated_at = now()`,
			orgID, c.id, n, by); err != nil {
			return "", err
		}
	}
	return strings.Join(parts, ". "), tx.Commit(ctx)
}

// Licensed: whether someone may use this app as far as licences go: assigned
// to them, or through a group with a seat left (always,
// for apps that aren't Keston products, and for support accounts).
func (s *Store) Licensed(ctx context.Context, u *User, clientID string) (bool, error) {
	if u.IsSupport() {
		return true, nil
	}
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM clients WHERE id = $2 AND builtin)
		OR EXISTS (SELECT 1 FROM user_licences WHERE user_id = $1 AND client_id = $2)
		OR EXISTS (SELECT 1 FROM effective_licences WHERE organisation_id = $3 AND user_id = $1 AND client_id = $2
			AND licensed)`, u.ID, clientID, u.OrganisationID).Scan(&ok)
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
