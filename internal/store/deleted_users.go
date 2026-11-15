package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Deleted users ────────────────────────────────────────────────────────
//
// Deleting a user signs them out everywhere, revokes their tokens and hides
// them (status 'deleted': they can't sign in, and aren't in lists or group
// members). They keep their group memberships, so for 30 days they can be
// restored as they were; then housekeeping removes them for good.

// DeletedUserDays: how long a deleted user can still be restored.
const DeletedUserDays = 30

var ErrLastGlobalAdmin = errors.New("last global admin")

// DeletedUser is a user in the recycle bin.
type DeletedUser struct {
	User
	DeletedAt  time.Time
	PurgeAfter time.Time
	// Who deleted them (nil: that user has gone too).
	DeletedBy     *string
	DeletedByName *string
}

// DeleteUser deletes someone in an organisation (see above). It refuses
// (ErrLastGlobalAdmin) if they're its last active global admin, and gives
// ErrNotFound if they aren't there or are already deleted.
func (s *Store) DeleteUser(ctx context.Context, orgID, userID, byID string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// One deletion at a time per organisation, so two admins deleting each
	// other at once can't leave it without a global admin.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organisations WHERE id = $1 FOR UPDATE`, orgID); err != nil {
		return err
	}
	var role, status string
	err = tx.QueryRow(ctx, `SELECT role, status FROM users WHERE id = $1 AND organisation_id = $2 FOR UPDATE`,
		userID, orgID).Scan(&role, &status)
	if err != nil {
		return notFound(err)
	}
	if status == "deleted" {
		return ErrNotFound
	}
	if role == "global_admin" && status == "active" {
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE organisation_id = $1 AND id <> $2
			AND role = 'global_admin' AND status = 'active' AND support_for IS NULL`, orgID, userID).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return ErrLastGlobalAdmin
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO deleted_users (user_id, deleted_by, previous_status, purge_after)
		VALUES ($1, $2, $3, now() + make_interval(days => $4))`, userID, byID, status, DeletedUserDays); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE users SET status = 'deleted', updated_at = now() WHERE id = $1`,
		`DELETE FROM sessions WHERE user_id = $1`,
		`DELETE FROM access_tokens WHERE user_id = $1`,
		`DELETE FROM refresh_tokens WHERE user_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RestoreUser brings a deleted user back as they were (active or
// disabled), with the groups they were in.
func (s *Store) RestoreUser(ctx context.Context, orgID, userID string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var previous string
	err = tx.QueryRow(ctx, `DELETE FROM deleted_users d USING users u
		WHERE d.user_id = $1 AND u.id = d.user_id AND u.organisation_id = $2 RETURNING d.previous_status`,
		userID, orgID).Scan(&previous)
	if err != nil {
		return notFound(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET status = $2, updated_at = now() WHERE id = $1`,
		userID, previous); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeletedUsers in an organisation, most recently deleted first.
func (s *Store) DeletedUsers(ctx context.Context, orgID string) ([]DeletedUser, error) {
	rows, err := s.DB.Query(ctx, `SELECT d.user_id::text, d.deleted_at, d.purge_after, d.deleted_by::text,
			(SELECT b.name FROM users b WHERE b.id = d.deleted_by)
		FROM deleted_users d JOIN users u ON u.id = d.user_id
		WHERE u.organisation_id = $1 ORDER BY d.deleted_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (DeletedUser, error) {
		var d DeletedUser
		err := r.Scan(&d.ID, &d.DeletedAt, &d.PurgeAfter, &d.DeletedBy, &d.DeletedByName)
		return d, err
	})
	if err != nil || len(out) == 0 {
		return out, err
	}
	ids := make([]string, len(out))
	for i := range out {
		ids[i] = out[i].ID
	}
	urows, err := s.DB.Query(ctx, `SELECT `+userColumns+` FROM users WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, err
	}
	byID := map[string]User{}
	if _, err := pgx.CollectRows(urows, func(r pgx.CollectableRow) (struct{}, error) {
		u, err := scanUser(r)
		if err == nil {
			byID[u.ID] = *u
		}
		return struct{}{}, err
	}); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].User = byID[out[i].ID]
	}
	return out, nil
}

// PurgeDeletedUsers removes users deleted more than 30 days ago, for good
// (their sessions, tokens, grants and group memberships go with them).
// Safe on every replica.
func (s *Store) PurgeDeletedUsers(ctx context.Context) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM users WHERE id IN
		(SELECT user_id FROM deleted_users WHERE purge_after <= now())`)
	return tag.RowsAffected(), err
}
