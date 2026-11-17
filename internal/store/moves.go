package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── Moving an account to another organisation ────────────────────────────
//
// A global admin of an account's home organisation asks to move it; a
// global admin of the receiving organisation accepts or declines. On
// acceptance the account's email becomes username@new-domain, it becomes a
// plain member of the new organisation (no groups, admin roles or licences
// carry over), and it's signed out everywhere.

var (
	// Special accounts can't move: Keston support accounts, TKG Admins, deleted ones.
	ErrMoveNotAllowed = errors.New("this account can't be moved")
	// username@new-domain already belongs to someone.
	ErrMoveEmailTaken = errors.New("the new email is taken")
	// They're the organisation's only global admin.
	ErrMoveLastAdmin = errors.New("the only global admin")
	// The receiving organisation isn't verified, or is the same one.
	ErrMoveOrganisation = errors.New("can't move to that organisation")
)

type AccountMove struct {
	ID                   string     `json:"id"`
	UserID               string     `json:"userId"`
	UserName             string     `json:"name"`
	OldEmail             string     `json:"oldEmail"`
	NewEmail             string     `json:"newEmail"`
	FromOrganisationID   string     `json:"fromOrganisationId"`
	FromOrganisationName string     `json:"fromOrganisationName"`
	ToOrganisationID     string     `json:"toOrganisationId"`
	ToOrganisationName   string     `json:"toOrganisationName"`
	Status               string     `json:"status"`
	RequestedByName      string     `json:"requestedByName"`
	DecidedByName        string     `json:"decidedByName"`
	CreatedAt            time.Time  `json:"createdAt"`
	DecidedAt            *time.Time `json:"decidedAt,omitempty"`
}

const moveColumns = `m.id::text, m.user_id::text, m.user_name, m.old_email, m.new_email, m.from_organisation_id::text,
	fo.name, m.to_organisation_id::text, tn.name, m.status, m.requested_by_name, m.decided_by_name, m.created_at, m.decided_at`

const moveFrom = ` FROM account_moves m JOIN organisations fo ON fo.id = m.from_organisation_id
	JOIN organisations tn ON tn.id = m.to_organisation_id`

func (s *Store) moves(ctx context.Context, where string, args ...any) ([]AccountMove, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+moveColumns+moveFrom+` WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AccountMove])
}

func (s *Store) MoveByID(ctx context.Context, id string) (*AccountMove, error) {
	if !IsUUID(id) {
		return nil, ErrNotFound
	}
	list, err := s.moves(ctx, `m.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// MovesOf: an organisation's pending requests (to or from it) and the
// last few decided ones.
func (s *Store) MovesOf(ctx context.Context, orgID string) ([]AccountMove, error) {
	return s.moves(ctx, `(m.from_organisation_id = $1 OR m.to_organisation_id = $1)
		AND (m.status = 'pending' OR m.decided_at > now() - interval '30 days')
		ORDER BY (m.status = 'pending') DESC, m.created_at DESC LIMIT 100`, orgID)
}

// PendingMovesTo: requests waiting for an organisation's global admins.
func (s *Store) PendingMovesTo(ctx context.Context, orgID string) ([]AccountMove, error) {
	return s.moves(ctx, `m.to_organisation_id = $1 AND m.status = 'pending' ORDER BY m.created_at`, orgID)
}

// movable: why this account can't be moved, nil if it can.
func (s *Store) movable(ctx context.Context, q pgx.Tx, u *User) error {
	if u.IsSupport() || u.PlatformAdmin || u.Status == "deleted" {
		return ErrMoveNotAllowed
	}
	if u.Role == "global_admin" {
		var others int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM users WHERE organisation_id = $1 AND id <> $2
			AND role = 'global_admin' AND status = 'active' AND support_for IS NULL`, u.OrganisationID, u.ID).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrMoveLastAdmin
		}
	}
	return nil
}

func emailIn(u *User, to *Organisation) string {
	local, _, _ := strings.Cut(u.Email, "@")
	return local + "@" + to.Domain // its primary domain
}

// RequestMove asks to move u to the organisation (ErrPending if one is
// already waiting).
func (s *Store) RequestMove(ctx context.Context, u *User, to *Organisation, by *User) (*AccountMove, error) {
	if to.ID == u.OrganisationID || !to.Verified || to.DeletionRequestedAt != nil {
		return nil, ErrMoveOrganisation
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.movable(ctx, tx, u); err != nil {
		return nil, err
	}
	newEmail := emailIn(u, to)
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1))`, newEmail).Scan(&taken); err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrMoveEmailTaken
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO account_moves (user_id, from_organisation_id, to_organisation_id, old_email,
			new_email, user_name, requested_by, requested_by_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id::text`,
		u.ID, u.OrganisationID, to.ID, u.Email, newEmail, u.Name, by.ID, by.Name).Scan(&id)
	if isUniqueViolation(err) {
		return nil, ErrPending
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.MoveByID(ctx, id)
}

// CancelMove withdraws a pending request (by the organisation asking).
func (s *Store) CancelMove(ctx context.Context, id, fromOrgID string, by *User) (bool, error) {
	if !IsUUID(id) {
		return false, nil
	}
	tag, err := s.DB.Exec(ctx, `UPDATE account_moves SET status = 'cancelled', decided_by = $3, decided_by_name = $4,
		decided_at = now() WHERE id = $1 AND from_organisation_id = $2 AND status = 'pending'`, id, fromOrgID, by.ID, by.Name)
	return tag.RowsAffected() == 1, err
}

// DecideMove: the receiving organisation accepts or declines. Accepting
// moves the account (ok is false if the request isn't pending, or isn't
// for this organisation). Everything happens in one transaction.
func (s *Store) DecideMove(ctx context.Context, id, toOrgID string, accept bool, by *User) (*AccountMove, bool, error) {
	if !IsUUID(id) {
		return nil, false, nil
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	var userID, fromID, newEmail string
	err = tx.QueryRow(ctx, `SELECT user_id::text, from_organisation_id::text, new_email FROM account_moves
		WHERE id = $1 AND to_organisation_id = $2 AND status = 'pending' FOR UPDATE`, id, toOrgID).Scan(&userID, &fromID, &newEmail)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !accept {
		if _, err := tx.Exec(ctx, `UPDATE account_moves SET status = 'declined', decided_by = $2, decided_by_name = $3,
			decided_at = now() WHERE id = $1`, id, by.ID, by.Name); err != nil {
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		m, err := s.MoveByID(ctx, id)
		return m, true, err
	}

	u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, userID))
	if err != nil {
		return nil, false, err
	}
	// Still where the request said, and still movable.
	if u.OrganisationID != fromID {
		return nil, false, ErrMoveNotAllowed
	}
	to, err := scanOrganisation(tx.QueryRow(ctx, `SELECT `+orgColumns+` FROM organisations WHERE id = $1`, toOrgID))
	if err != nil {
		return nil, false, err
	}
	if !to.Verified || to.DeletionRequestedAt != nil {
		return nil, false, ErrMoveOrganisation
	}
	if err := s.movable(ctx, tx, u); err != nil {
		return nil, false, err
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower($1) AND id <> $2)`,
		newEmail, userID).Scan(&taken); err != nil {
		return nil, false, err
	}
	if taken {
		return nil, false, ErrMoveEmailTaken
	}
	type step struct {
		sql  string
		args []any
	}
	for _, st := range []step{
		// The account itself: a plain member of the new organisation.
		{`UPDATE users SET organisation_id = $2, email = $3, role = 'member', platform_admin = FALSE, updated_at = now()
			WHERE id = $1`, []any{userID, toOrgID, newEmail}},
		// Nothing from the old organisation carries over.
		{`DELETE FROM user_roles WHERE user_id = $1`, []any{userID}},
		{`DELETE FROM user_licences WHERE user_id = $1`, []any{userID}},
		// Their manager, their reports' manager link to them, and organisation-defined attributes.
		{`UPDATE user_profiles SET manager_id = NULL, updated_at = now() WHERE user_id = $1 OR manager_id = $1`, []any{userID}},
		{`DELETE FROM user_attribute_values WHERE user_id = $1`, []any{userID}},
		{`DELETE FROM group_members WHERE user_id = $1 AND group_id IN (SELECT id FROM groups WHERE organisation_id = $2)`,
			[]any{userID, fromID}},
		// Now a member of the new organisation, so no longer its guest.
		{`UPDATE guest_memberships SET status = 'removed', admin_roles = '{}', responded_at = now(), updated_at = now()
			WHERE user_id = $1 AND organisation_id = $2 AND status IN ('pending', 'accepted')`, []any{userID, toOrgID}},
		{`DELETE FROM group_members WHERE user_id = $1 AND group_id IN (SELECT id FROM groups WHERE organisation_id = $2)`,
			[]any{userID, toOrgID}},
		// Signed out everywhere: their email and organisation changed.
		{`DELETE FROM sessions WHERE user_id = $1`, []any{userID}},
		{`DELETE FROM access_tokens WHERE user_id = $1`, []any{userID}},
		{`DELETE FROM refresh_tokens WHERE user_id = $1`, []any{userID}},
	} {
		if _, err := tx.Exec(ctx, st.sql, st.args...); err != nil {
			return nil, false, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE account_moves SET status = 'accepted', decided_by = $2, decided_by_name = $3,
		decided_at = now() WHERE id = $1`, id, by.ID, by.Name); err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	m, err := s.MoveByID(ctx, id)
	return m, true, err
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
