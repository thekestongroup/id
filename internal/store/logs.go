package store

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── Logs: admin actions and sign-ins ─────────────────────────────────────
//
// Both are written with one INSERT each, and never fail what's being
// logged: a write that fails is only reported in the server log. Rows are
// kept for LogRetention (see DeleteOldLogs).

// LogRetention: how long log entries are kept.
const LogRetention = 365 * 24 * time.Hour

// Admin actions, as recorded in the audit log. Keston Admin labels them.
const (
	ActionOrganisationCreated  = "organisation.created"
	ActionUserCreated          = "user.created"
	ActionUserUpdated          = "user.updated"
	ActionUserPictureChanged   = "user.picture_changed"
	ActionUserPictureRemoved   = "user.picture_removed"
	ActionUserPasswordReset    = "user.password_reset"
	ActionUserDisabled         = "user.disabled"
	ActionUserEnabled          = "user.enabled"
	ActionUserMFADisabled      = "user.mfa_disabled"
	ActionUserPasskeysRemoved  = "user.passkeys_removed"
	ActionUserDeleted          = "user.deleted"
	ActionUserRestored         = "user.restored"
	ActionUserLicences         = "user.licences_changed"
	ActionOrgLicences          = "organisation.licences_changed"
	ActionUserRoles            = "user.roles_changed"
	ActionPasswordChangeSet    = "user.password_change_required"
	ActionAccessPassIssued     = "user.access_pass_issued"
	ActionAccessPassRevoked    = "user.access_pass_revoked"
	ActionMFAPolicy            = "mfa_policy.changed"
	ActionOwnAppCreated        = "own_app.created"
	ActionOwnAppUpdated        = "own_app.updated"
	ActionOwnAppDeleted        = "own_app.deleted"
	ActionOwnAppSecret         = "own_app.secret_changed"
	ActionGroupCreated         = "group.created"
	ActionGroupRenamed         = "group.renamed"
	ActionGroupDeleted         = "group.deleted"
	ActionGroupMemberAdded     = "group.member_added"
	ActionGroupMemberRemoved   = "group.member_removed"
	ActionGroupPermissions     = "group.permissions_changed"
	ActionGroupLicences        = "group.licences_changed"
	ActionAppAccess            = "app.access_changed"
	ActionKestonAppCreated     = "keston_app.created"
	ActionKestonAppUpdated     = "keston_app.updated"
	ActionKestonAppRetired     = "keston_app.retired"
	ActionKestonAppRestored    = "keston_app.restored"
	ActionKestonAppSecret      = "keston_app.secret_changed"
	ActionSettings             = "settings.changed"
	ActionPasswordPolicy       = "password_policy.changed"
	ActionSupportRequested     = "support.requested"
	ActionSupportAllowed       = "support.allowed"
	ActionSupportDeclined      = "support.declined"
	ActionSupportEnded         = "support.ended"
	ActionSupportOpened        = "support.opened"
	ActionLockoutStarted       = "lockout.started"
	ActionLockoutDenied        = "lockout.denied"
	ActionLockoutCancelled     = "lockout.cancelled"
	ActionLockoutCompleted     = "lockout.completed"
	ActionDeletionScheduled    = "deletion.scheduled"
	ActionDeletionCancelled    = "deletion.cancelled"
	ActionOrganisationVerified = "organisation.verified"
	ActionPlatformSettings     = "platform_settings.changed"
	ActionGuestSetting         = "guests.setting_changed"
	ActionGuestInvited         = "guest.invited"
	ActionGuestAccepted        = "guest.accepted"
	ActionGuestDeclined        = "guest.declined"
	ActionGuestRemoved         = "guest.removed"
	ActionGuestLeft            = "guest.left"
	ActionGuestRoles           = "guest.roles_changed"
	ActionMoveRequested        = "move.requested"
	ActionMoveAccepted         = "move.accepted"
	ActionMoveDeclined         = "move.declined"
	ActionMoveCancelled        = "move.cancelled"
	// Recorded in the platform organisation's log: the organisation's own goes with it.
	ActionOrganisationDeletedNow = "organisation.deleted_now"
)

// What an action was done to.
const (
	TargetUser         = "user"
	TargetGroup        = "group"
	TargetApp          = "app"
	TargetOrganisation = "organisation"
)

// AuditEntry is one admin action.
type AuditEntry struct {
	OrganisationID string
	// Who did it; nil: Keston ID itself (housekeeping).
	Actor  *User
	Action string
	// What it was done to (TargetUser…), its ID and its name at the time.
	TargetType, TargetID, TargetName string
	// A short before → after, e.g. "Active → Disabled".
	Summary string
	IP      string
}

// Audit records an admin action.
func (s *Store) Audit(ctx context.Context, e AuditEntry) {
	if err := auditIn(context.WithoutCancel(ctx), s.DB, e); err != nil {
		slog.Warn("audit log", "action", e.Action, "organisation", e.OrganisationID, "error", err)
	}
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func auditIn(ctx context.Context, q execer, e AuditEntry) error {
	var actorID, staffID *string
	actorName, actorEmail := "Keston ID", ""
	if e.Actor != nil {
		actorID, actorName, actorEmail, staffID = &e.Actor.ID, e.Actor.Name, e.Actor.Email, e.Actor.SupportFor
	}
	// The staff member's name comes from the same statement (a support
	// account only knows their ID).
	_, err := q.Exec(ctx, `INSERT INTO audit_log (organisation_id, actor_id, actor_name,
			actor_email, support_staff_id, support_staff_name, action, target_type, target_id, target_name, summary, ip)
		VALUES ($1, $2, $3, $4, $5::uuid, (SELECT name FROM users WHERE id = $5::uuid), $6, $7, NULLIF($8, ''), $9, $10, $11)`,
		e.OrganisationID, actorID, actorName, actorEmail, staffID, e.Action, e.TargetType, e.TargetID,
		clip(e.TargetName, 200), clip(e.Summary, 1000), clip(e.IP, 64))
	return err
}

// Sign-in methods.
const (
	SignInPassword   = "password"
	SignInMFA        = "mfa"
	SignInBackupCode = "backup_code"
	SignInPasskey    = "passkey"
	SignInAccessPass = "access_pass"
	SignInSupport    = "support"
	// Signing in to an app (after Keston ID itself).
	SignInApp = "app"
)

// Why a sign-in failed.
const (
	ReasonUnknownUser    = "unknown_user"
	ReasonWrongPassword  = "wrong_password"
	ReasonLocked         = "locked"
	ReasonDisabled       = "disabled"
	ReasonExpired        = "expired"
	ReasonSupportAccount = "support_account"
	ReasonMFAFailed      = "mfa_failed"
	ReasonWrongPass      = "wrong_access_pass"
	ReasonAppDisabled    = "app_disabled"
	ReasonNoLicence      = "no_licence"
	ReasonUnverifiedOrg  = "organisation_unverified"
)

// SignIn is one sign-in attempt.
type SignIn struct {
	// Who; nil when nobody has Email.
	User  *User
	Email string
	// SignInPassword…
	Method string
	// The app, or the auth request it came from (either may be empty).
	ClientID, AuthRequestID string
	Success                 bool
	// Why it failed (ReasonWrongPassword…).
	Reason string
	// A support sign-in: the Keston staff member.
	Staff         *User
	IP, UserAgent string
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsUUID: s is a UUID (so it's safe to compare with a UUID column).
func IsUUID(s string) bool { return uuidRE.MatchString(s) }

// LogSignIn records a sign-in attempt. For an email nobody has, it's
// logged against the organisation with that domain, if there is one.
func (s *Store) LogSignIn(ctx context.Context, e SignIn) {
	var orgID, userID, staffID, staffName, authReq *string
	name, email := "", strings.ToLower(clip(strings.TrimSpace(e.Email), 254))
	if e.User != nil {
		orgID, userID, name, email = &e.User.OrganisationID, &e.User.ID, e.User.Name, e.User.Email
	}
	if e.Staff != nil {
		staffID, staffName = &e.Staff.ID, &e.Staff.Name
	}
	if e.ClientID == "" && IsUUID(e.AuthRequestID) {
		authReq = &e.AuthRequestID
	}
	_, err := s.DB.Exec(context.WithoutCancel(ctx), `INSERT INTO sign_in_log (organisation_id, user_id, user_name, email,
			method, client_id, success, reason, support_staff_id, support_staff_name, ip, user_agent)
		VALUES (COALESCE($1::uuid, (SELECT id FROM organisations WHERE lower(domain) = split_part($4, '@', 2))),
			$2, $3, $4, $5, COALESCE(NULLIF($6, ''), (SELECT client_id FROM auth_requests WHERE id = $7::uuid)),
			$8, $9, $10, $11, $12, $13)`,
		orgID, userID, name, email, e.Method, e.ClientID, authReq, e.Success, e.Reason, staffID, staffName,
		clip(e.IP, 64), clip(e.UserAgent, 500))
	if err != nil {
		slog.Warn("sign-in log", "method", e.Method, "error", err)
	}
}

// DeleteOldLogs deletes log entries older than LogRetention.
func (s *Store) DeleteOldLogs(ctx context.Context) error {
	for _, table := range []string{"audit_log", "sign_in_log"} {
		if _, err := s.DB.Exec(ctx, `DELETE FROM `+table+` WHERE created_at < now() - $1::interval`,
			LogRetention); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
	}
	return nil
}

// ── Reading them (Keston Admin → Logs) ───────────────────────────────────

// LogFilter narrows a log. Zero values mean no filter.
type LogFilter struct {
	OrganisationID string
	// Audit log: by them, to them, or through their support account. Sign-ins: theirs.
	// Any of these users (empty: everyone).
	UserIDs []string
	// Audit log: these actions.
	Actions []string
	// Sign-ins: successful (true) or failed (false), and why.
	Success *bool
	// Any of these reasons (empty: any).
	Reasons []string
	// From is inclusive, To exclusive.
	From, To *time.Time
	// Paging: entries older than this ID (the previous page's Next).
	Before int64
	Limit  int
}

type AuditRecord struct {
	ID               int64     `json:"id"`
	Action           string    `json:"action"`
	ActorID          *string   `json:"actorId"`
	ActorName        string    `json:"actorName"`
	ActorEmail       string    `json:"actorEmail"`
	SupportStaffID   *string   `json:"supportStaffId"`
	SupportStaffName *string   `json:"supportStaffName"`
	TargetType       string    `json:"targetType"`
	TargetID         *string   `json:"targetId"`
	TargetName       string    `json:"targetName"`
	Summary          string    `json:"summary"`
	IP               string    `json:"ip"`
	CreatedAt        time.Time `json:"createdAt"`
}

type SignInRecord struct {
	ID               int64     `json:"id"`
	UserID           *string   `json:"userId"`
	UserName         string    `json:"userName"`
	Email            string    `json:"email"`
	Method           string    `json:"method"`
	ClientID         *string   `json:"clientId"`
	ClientName       *string   `json:"clientName"`
	Success          bool      `json:"success"`
	Reason           string    `json:"reason"`
	SupportStaffName *string   `json:"supportStaffName"`
	IP               string    `json:"ip"`
	UserAgent        string    `json:"userAgent"`
	CreatedAt        time.Time `json:"createdAt"`
}

// where builds the shared part of a log query: organisation, dates, paging.
type where struct {
	sql  []string
	args []any
}

func (w *where) add(cond string, args ...any) {
	for _, a := range args {
		w.args = append(w.args, a)
		cond = strings.Replace(cond, "?", fmt.Sprintf("$%d", len(w.args)), 1)
	}
	w.sql = append(w.sql, cond)
}

func (f LogFilter) where(prefix string) *where {
	w := &where{}
	w.add(prefix+"organisation_id = ?", f.OrganisationID)
	if f.From != nil {
		w.add(prefix+"created_at >= ?", *f.From)
	}
	if f.To != nil {
		w.add(prefix+"created_at < ?", *f.To)
	}
	if f.Before > 0 {
		w.add(prefix+"id < ?", f.Before)
	}
	return w
}

func (f LogFilter) limit() int {
	if f.Limit <= 0 || f.Limit > 100 {
		return 50
	}
	return f.Limit
}

// AuditLog lists an organisation's admin actions, newest first. next is the
// Before for the next page (0: no more).
func (s *Store) AuditLog(ctx context.Context, f LogFilter) (out []AuditRecord, next int64, err error) {
	w := f.where("")
	if len(f.UserIDs) > 0 {
		w.add("(actor_id = ANY(?::uuid[]) OR support_staff_id = ANY(?::uuid[]) OR (target_type = 'user' AND target_id = ANY(?::text[])))",
			f.UserIDs, f.UserIDs, f.UserIDs)
	}
	if len(f.Actions) > 0 {
		w.add("action = ANY(?)", f.Actions)
	}
	rows, err := s.DB.Query(ctx, `SELECT id, action, actor_id::text, actor_name, actor_email, support_staff_id::text,
			support_staff_name, target_type, target_id, target_name, summary, ip, created_at
		FROM audit_log WHERE `+strings.Join(w.sql, " AND ")+fmt.Sprintf(` ORDER BY id DESC LIMIT %d`, f.limit()+1),
		w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[AuditRecord])
	if err != nil {
		return nil, 0, err
	}
	if len(out) > f.limit() {
		out = out[:f.limit()]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

// SignIns lists an organisation's sign-in attempts, newest first.
func (s *Store) SignIns(ctx context.Context, f LogFilter) (out []SignInRecord, next int64, err error) {
	w := f.where("l.")
	if len(f.UserIDs) > 0 {
		w.add("l.user_id = ANY(?::uuid[])", f.UserIDs)
	}
	if f.Success != nil {
		w.add("l.success = ?", *f.Success)
	}
	if len(f.Reasons) > 0 {
		w.add("l.reason = ANY(?)", f.Reasons)
	}
	rows, err := s.DB.Query(ctx, `SELECT l.id, l.user_id::text, l.user_name, l.email, l.method, l.client_id, c.name,
			l.success, l.reason, l.support_staff_name, l.ip, l.user_agent, l.created_at
		FROM sign_in_log l LEFT JOIN clients c ON c.id = l.client_id
		WHERE `+strings.Join(w.sql, " AND ")+fmt.Sprintf(` ORDER BY l.id DESC LIMIT %d`, f.limit()+1), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err = pgx.CollectRows(rows, pgx.RowToStructByPos[SignInRecord])
	if err != nil {
		return nil, 0, err
	}
	if len(out) > f.limit() {
		out = out[:f.limit()]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Don't cut a UTF-8 character in half.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
