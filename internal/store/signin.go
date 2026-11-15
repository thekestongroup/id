package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Sign-in requirements ─────────────────────────────────────────────────
//
// Required actions (choose a new password, set up MFA) come after the
// password and MFA and before any app gets tokens: the session's stage is
// 'actions' until they're done. See api/required.go.

// Session stages.
const (
	StagePassword = "password" // password done; MFA next
	StageActions  = "actions"  // signed in, but required actions are left
	StageVerified = "verified" // fully signed in
)

// SignInState: what decides someone's required actions, beyond the User.
type SignInState struct {
	PasswordChangeRequired bool
	MFARequired            bool
	// When MFA is required but there's a grace period: when it ends. Until
	// then they can put off setting it up. nil: required now.
	MFADeadline *time.Time
}

// SignInState reads whether they must change their password, and whether
// MFA is required for them (MFAMode): off, everyone (with the grace
// period), or custom rules (mfa_rules.go: the first matching rule, given
// where they're signing in from and to, else "Everyone else").
func (s *Store) SignInState(ctx context.Context, u *User, sc SignInContext) (*SignInState, error) {
	var st SignInState
	var mode string
	var grace int
	var start time.Time
	var everyoneElse bool
	err := s.DB.QueryRow(ctx, `SELECT u.password_change_required, o.mfa_mode, o.mfa_grace_days,
		greatest(o.mfa_required_since, u.created_at), o.mfa_required
		FROM users u JOIN organisations o ON o.id = u.organisation_id WHERE u.id = $1`, u.ID).
		Scan(&st.PasswordChangeRequired, &mode, &grace, &start, &everyoneElse)
	if err != nil {
		return nil, notFound(err)
	}
	switch mode {
	case MFARequired:
		st.MFARequired = true
		if grace > 0 {
			d := start.AddDate(0, 0, grace)
			st.MFADeadline = &d
		}
	case MFACustom:
		if st.MFARequired, err = s.mfaByRules(ctx, u, sc, everyoneElse); err != nil {
			return nil, err
		}
	}
	return &st, nil
}

// SkipMFAForNow: "Not now" to setting up MFA, for the rest of this session
// (only during the grace period).
func (s *Store) SkipMFAForNow(ctx context.Context, sessionID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE sessions SET mfa_skipped = TRUE WHERE id = $1`, sessionID)
	return err
}

// SetSessionStage moves a session between 'actions' and 'verified'. It
// reports whether it changed (so "signed in fully" runs once).
func (s *Store) SetSessionStage(ctx context.Context, id, from, to string) (*Session, bool, error) {
	x, err := scanSession(s.DB.QueryRow(ctx, `UPDATE sessions SET stage = $3 WHERE id = $1 AND stage = $2
		RETURNING `+sessionColumns, id, from, to))
	if err == ErrNotFound {
		return nil, false, nil
	}
	return x, err == nil, err
}

// AddSessionMethod records another way they proved who they are (e.g. "otp"
// once they've set up MFA during sign-in).
func (s *Store) AddSessionMethod(ctx context.Context, id, method string) (*Session, error) {
	return scanSession(s.DB.QueryRow(ctx, `UPDATE sessions SET amr = array_append(amr, $2) WHERE id = $1
		RETURNING `+sessionColumns, id, method))
}

// SetPasswordChangeRequired: they choose a new password next time they
// sign in (or not).
func (s *Store) SetPasswordChangeRequired(ctx context.Context, userID string, required bool) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET password_change_required = $2, updated_at = now() WHERE id = $1`,
		userID, required)
	return err
}

// SetRequiredPassword is the new password they chose at sign-in: it clears
// the requirement.
func (s *Store) SetRequiredPassword(ctx context.Context, userID, hash string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET password_hash = $2, password_changed_at = now(),
		password_change_required = FALSE, updated_at = now() WHERE id = $1`, userID, hash)
	return err
}

// SetPendingTOTP stores an authenticator being set up at sign-in, apart
// from the one in use.
func (s *Store) SetPendingTOTP(ctx context.Context, userID string, encrypted []byte) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET totp_pending = $2 WHERE id = $1`, userID, encrypted)
	return err
}

func (s *Store) PendingTOTP(ctx context.Context, userID string) ([]byte, error) {
	var b []byte
	err := s.DB.QueryRow(ctx, `SELECT totp_pending FROM users WHERE id = $1`, userID).Scan(&b)
	return b, notFound(err)
}

// UsePendingTOTP makes the pending authenticator the one in use, with new
// backup codes.
func (s *Store) UsePendingTOTP(ctx context.Context, userID string, backupCodeHashes []string) error {
	_, err := s.DB.Exec(ctx, `UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_enabled = TRUE,
		backup_codes = $2, updated_at = now() WHERE id = $1 AND totp_pending IS NOT NULL`, userID, backupCodeHashes)
	return err
}

// ── MFA mode (Keston Admin → Security → Manage MFA) ──────────────────────

// MFA modes.
const (
	MFAOff      = "off"
	MFARequired = "required"
	MFACustom   = "custom"
)

type MFAPolicy struct {
	// off, required (everyone) or custom (rules).
	Mode string `json:"mode"`
	// Required: days to set up MFA before it's enforced (0: at next sign-in).
	GracePeriodDays int `json:"gracePeriodDays"`
	// Custom rules: "Everyone else", for anyone no rule matches.
	Required bool `json:"required"`
}

func (s *Store) MFAPolicy(ctx context.Context, orgID string) (*MFAPolicy, error) {
	var p MFAPolicy
	if err := s.DB.QueryRow(ctx, `SELECT mfa_mode, mfa_grace_days, mfa_required FROM organisations WHERE id = $1`, orgID).
		Scan(&p.Mode, &p.GracePeriodDays, &p.Required); err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

// SetMFAMode: switching to required starts the grace period from now.
func (s *Store) SetMFAMode(ctx context.Context, orgID, mode string) error {
	_, err := s.DB.Exec(ctx, `UPDATE organisations SET mfa_mode = $2,
		mfa_required_since = CASE WHEN $2 = 'required' AND mfa_mode <> 'required' THEN now() ELSE mfa_required_since END,
		updated_at = now() WHERE id = $1`, orgID, mode)
	return err
}

func (s *Store) SetMFAGraceDays(ctx context.Context, orgID string, days int) error {
	_, err := s.DB.Exec(ctx, `UPDATE organisations SET mfa_grace_days = $2, updated_at = now() WHERE id = $1`,
		orgID, days)
	return err
}

// SetMFARequired: the custom rules' default.
func (s *Store) SetMFARequired(ctx context.Context, orgID string, required bool) error {
	_, err := s.DB.Exec(ctx, `UPDATE organisations SET mfa_required = $2, updated_at = now() WHERE id = $1`,
		orgID, required)
	return err
}

// ── Temporary access passes ──────────────────────────────────────────────

type AccessPass struct {
	ID         string     `json:"id"`
	OneTime    bool       `json:"oneTime"`
	CreatedBy  *string    `json:"createdBy"` // their name, if they're still here
	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
}

// Usable: not revoked, not expired, and (one-time) not used.
func (p AccessPass) Usable(now time.Time) bool {
	return p.RevokedAt == nil && p.ExpiresAt.After(now) && !(p.OneTime && p.LastUsedAt != nil)
}

const accessPassColumns = `p.id::text, p.one_time, (SELECT c.name FROM users c WHERE c.id = p.created_by),
	p.created_at, p.expires_at, p.last_used_at, p.revoked_at`

func (s *Store) CreateAccessPass(ctx context.Context, userID, createdBy, codeHash string, oneTime bool,
	ttl time.Duration) (*AccessPass, error) {
	rows, err := s.DB.Query(ctx, `INSERT INTO access_passes AS p (user_id, code_hash, one_time, created_by, expires_at)
		VALUES ($1, $2, $3, $4, now() + $5::interval) RETURNING `+accessPassColumns,
		userID, codeHash, oneTime, createdBy, ttl)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[AccessPass])
	return &p, err
}

// AccessPasses: someone's passes from the last week, newest first.
func (s *Store) AccessPasses(ctx context.Context, userID string) ([]AccessPass, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+accessPassColumns+` FROM access_passes p
		WHERE p.user_id = $1 AND p.expires_at > now() - interval '7 days' ORDER BY p.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AccessPass])
}

func (s *Store) RevokeAccessPass(ctx context.Context, userID, passID string) error {
	tag, err := s.DB.Exec(ctx, `UPDATE access_passes SET revoked_at = coalesce(revoked_at, now())
		WHERE user_id = $1 AND id::text = $2`, userID, passID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// UseAccessPass signs in with a pass, if it's one of theirs and still
// usable. A one-time pass stops working here (atomically, so it can't be
// used twice at once).
func (s *Store) UseAccessPass(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE access_passes SET last_used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND revoked_at IS NULL AND expires_at > now()
		AND NOT (one_time AND last_used_at IS NOT NULL)`, userID, codeHash)
	return tag.RowsAffected() == 1, err
}
