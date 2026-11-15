package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thekestongroup/id/internal/secret"
)

// LockoutWait is how long global admins have to deny a lockout request.
const LockoutWait = 72 * time.Hour

// SupportAccessFor is how long access granted by the lockout procedure lasts.
const SupportAccessFor = 7 * 24 * time.Hour

type SupportRequest struct {
	ID          string     `json:"id"`
	RequestedBy *string    `json:"requestedBy"`
	Requester   *string    `json:"requester"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	Via         string     `json:"via"`
	DecidedBy   *string    `json:"decidedBy"`
	DecidedAt   *time.Time `json:"decidedAt"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

type LockoutRequest struct {
	ID          string     `json:"id"`
	RequestedBy *string    `json:"requestedBy"`
	Requester   *string    `json:"requester"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	EffectiveAt time.Time  `json:"effectiveAt"`
	DecidedBy   *string    `json:"decidedBy"`
	DecidedAt   *time.Time `json:"decidedAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// CompleteDueLockouts finishes lockout requests nobody denied in time: each
// grants support access for SupportAccessFor. Safe on every replica (the
// update only matches pending rows once).
func (s *Store) CompleteDueLockouts(ctx context.Context) ([]LockoutDone, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `UPDATE lockout_requests SET status = 'completed', decided_at = now()
		WHERE status = 'pending' AND effective_at <= now()
		RETURNING id, organisation_id, requested_by, reason`)
	if err != nil {
		return nil, err
	}
	done, err := pgx.CollectRows(rows, pgx.RowToStructByPos[LockoutDone])
	if err != nil {
		return nil, err
	}
	for _, d := range done {
		if _, err := tx.Exec(ctx, `INSERT INTO support_requests (organisation_id, requested_by, reason, status, via,
				decided_at, expires_at)
			VALUES ($1, $2, $3, 'approved', 'lockout', now(), now() + $4::interval)`,
			d.OrganisationID, d.RequestedBy, d.Reason, SupportAccessFor); err != nil {
			return nil, err
		}
		if d.RequestedBy != nil {
			if err := createSupportAccount(ctx, tx, d.OrganisationID, *d.RequestedBy,
				time.Now().Add(SupportAccessFor)); err != nil {
				return nil, err
			}
		}
	}
	return done, tx.Commit(ctx)
}

type LockoutDone struct {
	ID             string
	OrganisationID string
	RequestedBy    *string
	Reason         string
}

// SupportAccess: Keston support can see this organisation's accounts until
// the returned time (nil: no access now).
func (s *Store) SupportAccess(ctx context.Context, orgID string) (*time.Time, error) {
	if _, err := s.CompleteDueLockouts(ctx); err != nil {
		return nil, err
	}
	var until *time.Time
	err := s.DB.QueryRow(ctx, `SELECT max(expires_at) FROM support_requests
		WHERE organisation_id = $1 AND status = 'approved' AND expires_at > now()`, orgID).Scan(&until)
	return until, err
}

const supportColumns = `r.id, r.requested_by, (SELECT u.name FROM users u WHERE u.id = r.requested_by), r.reason,
	r.status, r.via, r.decided_by, r.decided_at, r.expires_at, r.created_at`

func (s *Store) SupportRequests(ctx context.Context, orgID string) ([]SupportRequest, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+supportColumns+` FROM support_requests r
		WHERE r.organisation_id = $1 ORDER BY r.created_at DESC LIMIT 20`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SupportRequest])
}

func (s *Store) RequestSupport(ctx context.Context, orgID, userID, reason string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `INSERT INTO support_requests (organisation_id, requested_by, reason)
		VALUES ($1, $2, $3) RETURNING id`, orgID, userID, reason).Scan(&id)
	return id, err
}

// DecideSupport approves (for `for`) or denies a pending request.
func (s *Store) DecideSupport(ctx context.Context, orgID, requestID, userID string, approve bool,
	duration time.Duration) (bool, error) {
	status := "denied"
	var expires any
	if approve {
		status = "approved"
		expires = time.Now().Add(duration)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var requester *string
	err = tx.QueryRow(ctx, `UPDATE support_requests SET status = $4, decided_by = $3, decided_at = now(),
		expires_at = $5 WHERE id = $2 AND organisation_id = $1 AND status = 'pending' RETURNING requested_by`,
		orgID, requestID, userID, status, expires).Scan(&requester)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if approve && requester != nil {
		if err := createSupportAccount(ctx, tx, orgID, *requester, time.Now().Add(duration)); err != nil {
			return false, err
		}
	}
	return true, tx.Commit(ctx)
}

// RevokeSupport ends every approved support access now.
func (s *Store) RevokeSupport(ctx context.Context, orgID, userID string) error {
	if _, err := s.DB.Exec(ctx, `UPDATE support_requests SET status = 'revoked', decided_by = $2, decided_at = now()
		WHERE organisation_id = $1 AND status = 'approved' AND expires_at > now()`, orgID, userID); err != nil {
		return err
	}
	return s.DeleteSupportAccounts(ctx, orgID)
}

const lockoutColumns = `r.id, r.requested_by, (SELECT u.name FROM users u WHERE u.id = r.requested_by), r.reason,
	r.status, r.effective_at, r.decided_by, r.decided_at, r.created_at`

func (s *Store) LockoutRequests(ctx context.Context, orgID string) ([]LockoutRequest, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+lockoutColumns+` FROM lockout_requests r
		WHERE r.organisation_id = $1 ORDER BY r.created_at DESC LIMIT 20`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LockoutRequest])
}

// StartLockout begins the procedure, unless one is already pending.
func (s *Store) StartLockout(ctx context.Context, orgID, userID, reason string) (*LockoutRequest, error) {
	var pending bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM lockout_requests
		WHERE organisation_id = $1 AND status = 'pending')`, orgID).Scan(&pending); err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrPending
	}
	rows, err := s.DB.Query(ctx, `WITH r AS (INSERT INTO lockout_requests (organisation_id, requested_by, reason,
			effective_at) VALUES ($1, $2, $3, now() + $4::interval) RETURNING *)
		SELECT `+lockoutColumns+` FROM r`, orgID, userID, reason, LockoutWait)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[LockoutRequest])
	return &l, err
}

// DecideLockout: a global admin denies it, or Keston staff cancel it.
func (s *Store) DecideLockout(ctx context.Context, orgID, lockoutID, userID, status string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE lockout_requests SET status = $4, decided_by = $3, decided_at = now()
		WHERE id = $2 AND organisation_id = $1 AND status = 'pending'`, orgID, lockoutID, userID, status)
	return tag.RowsAffected() == 1, err
}

// GlobalAdmins of an organisation, to notify.
func (s *Store) GlobalAdmins(ctx context.Context, orgID string) ([]User, error) {
	all, err := s.UsersInOrganisation(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []User
	for _, u := range all {
		if u.Role == "global_admin" && u.Status == "active" {
			out = append(out, u)
		}
	}
	return out, nil
}

// ── Notifications ────────────────────────────────────────────────────────

type Notification struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Link      string     `json:"link"`
	ReadAt    *time.Time `json:"readAt"`
	CreatedAt time.Time  `json:"createdAt"`
}

func (s *Store) Notify(ctx context.Context, userIDs []string, kind, title, body, link string) error {
	for _, id := range userIDs {
		if _, err := s.DB.Exec(ctx, `INSERT INTO notifications (user_id, type, title, body, link)
			VALUES ($1, $2, $3, $4, $5)`, id, kind, title, body, link); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Notifications(ctx context.Context, userID string) ([]Notification, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, type, title, body, link, read_at, created_at FROM notifications
		WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Notification])
}

func (s *Store) MarkNotificationsRead(ctx context.Context, userID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE notifications SET read_at = now() WHERE user_id = $1 AND read_at IS NULL`, userID)
	return err
}

func (s *Store) DeleteNotifications(ctx context.Context, userID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM notifications WHERE user_id = $1`, userID)
	return err
}

// ErrPending: there's already a pending request of this kind.
var ErrPending = errors.New("already pending")

// ── Support accounts ─────────────────────────────────────────────────────

// createSupportAccount gives a Keston staff member a temporary account in an
// organisation, as a global admin there, until `until`. Its password is
// random and never shown: it's only opened from the staff member's own
// account. With one already there, it just lasts longer.
func createSupportAccount(ctx context.Context, q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, orgID, staffID string, until time.Time) error {
	_, err := q.Exec(ctx, `
		WITH staff AS (SELECT name FROM users WHERE id = $2),
		     org AS (SELECT domain FROM organisations WHERE id = $1)
		INSERT INTO users (organisation_id, email, name, role, password_hash, support_for, expires_at)
		SELECT $1, 'keston-support-' || substr(md5($2::text), 1, 8) || '@' || org.domain,
		       staff.name || ' (Keston support)', 'global_admin', $3, $2, $4
		FROM staff, org
		ON CONFLICT (lower(email)) DO UPDATE SET expires_at = greatest(users.expires_at, $4), status = 'active'`,
		orgID, staffID, "!support-account-no-password:"+secret.Token(), until)
	return err
}

// SupportAccount is a staff member's usable support account in an
// organisation, if they have one.
func (s *Store) SupportAccount(ctx context.Context, orgID, staffID string) (*User, error) {
	u, err := scanUser(s.DB.QueryRow(ctx, `SELECT `+userColumns+` FROM users
		WHERE organisation_id = $1 AND support_for = $2 AND status = 'active' AND expires_at > now()`, orgID, staffID))
	return u, err
}

// DeleteSupportAccounts removes an organisation's support accounts (access
// ended), which also signs them out of everything.
func (s *Store) DeleteSupportAccounts(ctx context.Context, orgID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM users WHERE organisation_id = $1 AND support_for IS NOT NULL`, orgID)
	return err
}

// DeleteExpiredSupportAccounts tidies up support accounts past their time.
func (s *Store) DeleteExpiredSupportAccounts(ctx context.Context) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM users WHERE support_for IS NOT NULL AND expires_at <= now()`)
	return err
}
