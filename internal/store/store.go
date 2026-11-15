// Package store is Keston ID's data access: every query lives here.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/thekestongroup/id/internal/secret"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	DB  *pgxpool.Pool
	Box *secret.Box
}

func New(db *pgxpool.Pool, box *secret.Box) *Store { return &Store{DB: db, Box: box} }

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ── Users ────────────────────────────────────────────────────────────────

type User struct {
	ID             string
	Email          string
	Name           string
	OrganisationID string
	Organisation   string // the organisation's name
	Role           string // "member" or "global_admin"
	// Keston staff: in the platform organisation (The Keston Group), as a
	// global admin or marked platform_admin.
	PlatformAdmin bool
	// A support account: the Keston staff member it's for (nil: a normal
	// account), and when it stops working.
	SupportFor *string
	ExpiresAt  *time.Time
	// When the profile picture last changed; nil: no picture.
	PictureUpdatedAt  *time.Time
	PasswordHash      string
	PasswordChangedAt time.Time
	TOTPSecret        []byte // encrypted
	TOTPEnabled       bool
	BackupCodes       []string
	Status            string
	FailedLogins      int
	LockedUntil       *time.Time
	CreatedAt         time.Time
}

// The organisation's name comes from a subquery, so the same columns work
// after SELECT … FROM users and after INSERT/UPDATE … RETURNING.
const userColumns = `id, email, name, organisation_id,
	(SELECT o.name FROM organisations o WHERE o.id = users.organisation_id) AS organisation_name, role,
	(EXISTS (SELECT 1 FROM organisations p WHERE p.id = users.organisation_id AND p.is_platform)
		AND (platform_admin OR role = 'global_admin')) AS is_platform_admin,
	support_for, expires_at, picture_updated_at,
	password_hash, password_changed_at, totp_secret, totp_enabled, backup_codes, status, failed_logins, locked_until,
	created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.OrganisationID, &u.Organisation, &u.Role, &u.PlatformAdmin,
		&u.SupportFor, &u.ExpiresAt, &u.PictureUpdatedAt, &u.PasswordHash, &u.PasswordChangedAt, &u.TOTPSecret, &u.TOTPEnabled, &u.BackupCodes, &u.Status, &u.FailedLogins,
		&u.LockedUntil, &u.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.DB.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.DB.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email))
}

// NewUser is an account to create. Email is username@ the organisation's
// domain.
type NewUser struct {
	OrganisationID string
	Email          string
	Name           string
	Role           string
	// Keston staff: in the platform organisation (The Keston Group), as a
	// global admin or marked platform_admin.
	PlatformAdmin bool
	// A support account: the Keston staff member it's for (nil: a normal
	// account), and when it stops working.
	SupportFor   *string
	ExpiresAt    *time.Time
	PasswordHash string
}

func (s *Store) CreateUser(ctx context.Context, q Querier, n NewUser) (*User, error) {
	if n.Role == "" {
		n.Role = "member"
	}
	return scanUser(q.QueryRow(ctx, `INSERT INTO users (organisation_id, email, name, role, platform_admin, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+userColumns,
		n.OrganisationID, n.Email, n.Name, n.Role, n.PlatformAdmin, n.PasswordHash))
}

func (s *Store) UsersInOrganisation(ctx context.Context, orgID string) ([]User, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+userColumns+` FROM users WHERE organisation_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) {
		u, err := scanUser(r)
		if err != nil {
			return User{}, err
		}
		return *u, nil
	})
}

// SetUserStatus disables or re-enables an account. Disabling also signs it
// out everywhere and stops its apps' tokens working.
func (s *Store) SetUserStatus(ctx context.Context, userID, status string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE users SET status = $2, updated_at = now() WHERE id = $1`, userID, status); err != nil {
		return err
	}
	if status == "disabled" {
		for _, q := range []string{
			`DELETE FROM sessions WHERE user_id = $1`,
			`DELETE FROM access_tokens WHERE user_id = $1`,
			`DELETE FROM refresh_tokens WHERE user_id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, userID); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// ResetPassword sets a new password for someone (by an admin), unlocks the
// account and signs it out everywhere.
func (s *Store) ResetPassword(ctx context.Context, userID, hash string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(), failed_logins = 0,
		locked_until = NULL, updated_at = now() WHERE id = $1`, userID, hash); err != nil {
		return err
	}
	// Signed out everywhere: Keston ID and every app.
	for _, q := range []string{
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

func (s *Store) SetPlatformAdmin(ctx context.Context, email string, on bool) error {
	tag, err := s.DB.Exec(ctx, `UPDATE users SET platform_admin = $2 WHERE lower(email) = lower($1)`, email, on)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RecordLogin counts failed attempts; five in a row lock the account for 15
// minutes, which slows password guessing across every replica.
func (s *Store) RecordLogin(ctx context.Context, userID string, ok bool) error {
	if ok {
		_, err := s.DB.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, userID)
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE users SET failed_logins = failed_logins + 1,
		locked_until = CASE WHEN failed_logins + 1 >= 5 THEN now() + interval '15 minutes' ELSE locked_until END
		WHERE id = $1`, userID)
	return err
}

func (s *Store) SetPassword(ctx context.Context, userID, hash string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now()
		WHERE id = $1`, userID, hash)
	return err
}

// SetTOTP stores a new (encrypted) secret, not yet enabled.
func (s *Store) SetTOTP(ctx context.Context, userID string, encrypted []byte) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET totp_secret = $2, totp_enabled = FALSE, updated_at = now() WHERE id = $1`,
		userID, encrypted)
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, userID string, backupCodeHashes []string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET totp_enabled = TRUE, backup_codes = $2, updated_at = now() WHERE id = $1`,
		userID, backupCodeHashes)
	return err
}

func (s *Store) DisableTOTP(ctx context.Context, userID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, backup_codes = '{}',
		updated_at = now() WHERE id = $1`, userID)
	return err
}

// UseBackupCode removes a backup code if it's there, so each works once.
func (s *Store) UseBackupCode(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE users SET backup_codes = array_remove(backup_codes, $2)
		WHERE id = $1 AND $2 = ANY (backup_codes)`, userID, codeHash)
	return tag.RowsAffected() == 1, err
}

// ── Sessions ─────────────────────────────────────────────────────────────

type Session struct {
	ID         string
	UserID     string
	Stage      string
	AMR        []string
	AuthTime   time.Time
	UserAgent  string
	IP         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

const sessionColumns = `id, user_id, stage, amr, auth_time, user_agent, ip, created_at, last_seen_at, expires_at`

func scanSession(row pgx.Row) (*Session, error) {
	var x Session
	if err := row.Scan(&x.ID, &x.UserID, &x.Stage, &x.AMR, &x.AuthTime, &x.UserAgent, &x.IP, &x.CreatedAt,
		&x.LastSeenAt, &x.ExpiresAt); err != nil {
		return nil, notFound(err)
	}
	return &x, nil
}

// CreateSession returns the cookie token; only its hash is stored.
func (s *Store) CreateSession(ctx context.Context, userID, stage string, amr []string, userAgent, ip string,
	ttl time.Duration) (string, *Session, error) {
	token := secret.Token()
	x, err := scanSession(s.DB.QueryRow(ctx, `INSERT INTO sessions (id, user_id, stage, amr, user_agent, ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval) RETURNING `+sessionColumns,
		secret.Hash(token), userID, stage, amr, userAgent, ip, ttl))
	return token, x, err
}

// SessionByToken finds a live session and notes it was used.
func (s *Store) SessionByToken(ctx context.Context, token string) (*Session, error) {
	return scanSession(s.DB.QueryRow(ctx, `UPDATE sessions SET last_seen_at = now()
		WHERE id = $1 AND expires_at > now() RETURNING `+sessionColumns, secret.Hash(token)))
}

// VerifySession records MFA (the second factor).
func (s *Store) VerifySession(ctx context.Context, id string, method string) (*Session, error) {
	return scanSession(s.DB.QueryRow(ctx, `UPDATE sessions SET stage = 'verified', amr = array_append(amr, $2),
		auth_time = now() WHERE id = $1 RETURNING `+sessionColumns, id, method))
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *Store) SessionsForUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Session, error) {
		x, err := scanSession(r)
		if err != nil {
			return Session{}, err
		}
		return *x, nil
	})
}

// DeleteOtherSessions signs someone out everywhere else, e.g. after a
// password change.
func (s *Store) DeleteOtherSessions(ctx context.Context, userID, keepID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id <> $2`, userID, keepID)
	return err
}

// Cleanup deletes expired rows. Safe to run on every replica.
func (s *Store) Cleanup(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM sessions WHERE expires_at < now()`,
		`DELETE FROM auth_requests WHERE expires_at < now()`,
		`DELETE FROM access_tokens WHERE expires_at < now()`,
		`DELETE FROM refresh_tokens WHERE expires_at < now()`,
	} {
		if _, err := s.DB.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// UpdateProfile changes someone's name and/or email (nil: unchanged).
func (s *Store) UpdateProfile(ctx context.Context, userID string, name, email *string) (*User, error) {
	return scanUser(s.DB.QueryRow(ctx, `UPDATE users SET name = coalesce($2, name), email = coalesce($3, email),
		updated_at = now() WHERE id = $1 RETURNING `+userColumns, userID, name, email))
}

// SetPicture sets (or with nil data, removes) a profile picture.
func (s *Store) SetPicture(ctx context.Context, userID string, data []byte, contentType string) error {
	if data == nil {
		_, err := s.DB.Exec(ctx, `UPDATE users SET picture = NULL, picture_type = NULL, picture_updated_at = NULL
			WHERE id = $1`, userID)
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE users SET picture = $2, picture_type = $3, picture_updated_at = now()
		WHERE id = $1`, userID, data, contentType)
	return err
}

func (s *Store) Picture(ctx context.Context, userID string) ([]byte, string, error) {
	var data []byte
	var contentType *string
	err := s.DB.QueryRow(ctx, `SELECT picture, picture_type FROM users WHERE id = $1 AND picture IS NOT NULL`,
		userID).Scan(&data, &contentType)
	if err != nil {
		return nil, "", notFound(err)
	}
	return data, deref(contentType), nil
}

func (s *Store) SetRole(ctx context.Context, userID, role string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET role = $2, updated_at = now() WHERE id = $1`, userID, role)
	return err
}

// Usable: active, and (for a support account) not expired.
func (u *User) Usable() bool {
	return u.Status == "active" && (u.ExpiresAt == nil || u.ExpiresAt.After(time.Now()))
}

// IsSupport: a temporary Keston support account.
func (u *User) IsSupport() bool { return u.SupportFor != nil }
