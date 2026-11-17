package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Security alerts ──────────────────────────────────────────────────────
//
// RaiseAlert records something worth a global admin's attention (an admin
// was added, MFA turned off, many failed sign-ins…) and hands it to every
// registered AlertSink. In-app notifications (the bell) are the only sink
// today; email delivery is another sink (RegisterAlertSink), with no change
// to the places that raise alerts.

// Alert kinds.
const (
	AlertAdminAdded      = "admin_added"
	AlertAdminRole       = "admin_role_granted"
	AlertMFAOff          = "mfa_off"
	AlertPasswordWeaker  = "password_policy_weakened"
	AlertFailedSignIns   = "failed_sign_ins"
	AlertAccountLocked   = "account_locked"
	AlertNewCountry      = "new_country"
	AlertSeverityInfo    = "info"
	AlertSeverityWarning = "warning"
	AlertSeverityHigh    = "critical"
)

// AlertKinds, for filtering.
var AlertKinds = []string{AlertAdminAdded, AlertAdminRole, AlertMFAOff, AlertPasswordWeaker,
	AlertFailedSignIns, AlertAccountLocked, AlertNewCountry}

const (
	// Many failed sign-ins: this many for one account within the window.
	FailedSignInLimit  = 10
	FailedSignInWindow = 10 * time.Minute
)

// NewAlert is what the places that notice something pass in.
type NewAlert struct {
	OrganisationID string
	Kind, Severity string
	// Who it's about (may be empty).
	SubjectID, SubjectName string
	// Details for translating it (country, count, who did it…).
	Params map[string]any
	// English text for notifications and email.
	Title, Body string
	// The same thing within this long isn't raised again (key: Kind and
	// SubjectID unless DedupeKey is set; 0: never merged).
	DedupeKey string
	DedupeFor time.Duration
}

type Alert struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Severity    string         `json:"severity"`
	SubjectID   *string        `json:"subjectId"`
	SubjectName string         `json:"subjectName"`
	Params      map[string]any `json:"params"`
	Title       string         `json:"title"`
	Body        string         `json:"body"`
	CreatedAt   time.Time      `json:"createdAt"`
	// Where it was raised (not in JSON).
	OrganisationID string `json:"-"`
}

// AlertSink delivers a new alert to the organisation's global admins.
type AlertSink interface {
	Deliver(ctx context.Context, s *Store, a Alert, admins []User) error
}

// InAppSink: a notification in Keston Admin's bell, linking to the Alerts page.
type InAppSink struct{}

func (InAppSink) Deliver(ctx context.Context, s *Store, a Alert, admins []User) error {
	ids := make([]string, len(admins))
	for i, u := range admins {
		ids[i] = u.ID
	}
	kind := "warning"
	if a.Severity == AlertSeverityInfo {
		kind = "info"
	} else if a.Severity == AlertSeverityHigh {
		kind = "error"
	}
	return s.Notify(ctx, ids, kind, a.Title, a.Body, "/organisations/"+a.OrganisationID+"/security/alerts")
}

var (
	sinkMu     sync.RWMutex
	alertSinks = []AlertSink{InAppSink{}}
)

// RegisterAlertSink adds another way alerts are delivered (email, a webhook…).
func RegisterAlertSink(sink AlertSink) {
	sinkMu.Lock()
	defer sinkMu.Unlock()
	alertSinks = append(alertSinks, sink)
}

// RaiseAlert records the alert and delivers it, unless the same one was
// raised within DedupeFor. It reports whether a new alert was raised. It
// never fails the caller's action: problems are logged.
func (s *Store) RaiseAlert(ctx context.Context, n NewAlert) bool {
	ctx = context.WithoutCancel(ctx)
	a, err := s.insertAlert(ctx, n)
	if err != nil {
		slog.Warn("security alert", "kind", n.Kind, "organisation", n.OrganisationID, "error", err)
		return false
	}
	if a == nil {
		return false
	}
	admins, err := s.GlobalAdmins(ctx, n.OrganisationID)
	if err != nil {
		slog.Warn("security alert recipients", "kind", n.Kind, "error", err)
		return true
	}
	real := admins[:0]
	for _, u := range admins {
		if !u.IsSupport() {
			real = append(real, u)
		}
	}
	sinkMu.RLock()
	sinks := append([]AlertSink(nil), alertSinks...)
	sinkMu.RUnlock()
	for _, sink := range sinks {
		if err := sink.Deliver(ctx, s, *a, real); err != nil {
			slog.Warn("security alert delivery", "kind", n.Kind, "sink", fmt.Sprintf("%T", sink), "error", err)
		}
	}
	return true
}

func (s *Store) insertAlert(ctx context.Context, n NewAlert) (*Alert, error) {
	if n.Severity == "" {
		n.Severity = AlertSeverityWarning
	}
	if n.Params == nil {
		n.Params = map[string]any{}
	}
	params, err := json.Marshal(n.Params)
	if err != nil {
		return nil, err
	}
	key := n.DedupeKey
	if key == "" {
		key = n.Kind + ":" + n.SubjectID
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// One at a time per organisation and key, so two requests at once
	// can't both raise it.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "alert:"+n.OrganisationID+":"+key); err != nil {
		return nil, err
	}
	if n.DedupeFor > 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM security_alerts WHERE organisation_id = $1
			AND dedupe_key = $2 AND created_at > now() - make_interval(secs => $3))`,
			n.OrganisationID, key, n.DedupeFor.Seconds()).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, nil
		}
	}
	a := Alert{OrganisationID: n.OrganisationID, Params: n.Params}
	var sub any
	if IsUUID(n.SubjectID) {
		sub = n.SubjectID
	}
	if err := tx.QueryRow(ctx, `INSERT INTO security_alerts (organisation_id, kind, severity, subject_id, subject_name,
			params, title, body, dedupe_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, kind, severity, subject_id::text, subject_name, title, body, created_at`,
		n.OrganisationID, n.Kind, n.Severity, sub, clip(n.SubjectName, 200), params, clip(n.Title, 200),
		clip(n.Body, 1000), key).
		Scan(&a.ID, &a.Kind, &a.Severity, &a.SubjectID, &a.SubjectName, &a.Title, &a.Body, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, tx.Commit(ctx)
}

// AlertFilter: which alerts to list.
type AlertFilter struct {
	OrganisationID string
	Kinds          []string
	Severities     []string
	From, To       *time.Time
	// Only before this time (the previous page's last alert).
	Before *time.Time
	Limit  int
}

// SecurityAlerts: newest first, with the time to pass as Before for the
// next page (nil: no more).
func (s *Store) SecurityAlerts(ctx context.Context, f AlertFilter) ([]Alert, *time.Time, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	w := []string{"organisation_id = $1"}
	args := []any{f.OrganisationID}
	add := func(cond string, v any) {
		args = append(args, v)
		w = append(w, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if len(f.Kinds) > 0 {
		add("kind = ANY(?)", f.Kinds)
	}
	if len(f.Severities) > 0 {
		add("severity = ANY(?)", f.Severities)
	}
	if f.From != nil {
		add("created_at >= ?", *f.From)
	}
	if f.To != nil {
		add("created_at < ?", *f.To)
	}
	if f.Before != nil {
		add("created_at < ?", *f.Before)
	}
	args = append(args, limit+1)
	rows, err := s.DB.Query(ctx, `SELECT id, kind, severity, subject_id::text, subject_name, params, title, body, created_at
		FROM security_alerts WHERE `+strings.Join(w, " AND ")+
		fmt.Sprintf(" ORDER BY created_at DESC, id LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Alert, error) {
		var a Alert
		var raw []byte
		if err := r.Scan(&a.ID, &a.Kind, &a.Severity, &a.SubjectID, &a.SubjectName, &raw, &a.Title, &a.Body, &a.CreatedAt); err != nil {
			return a, err
		}
		a.Params = map[string]any{}
		_ = json.Unmarshal(raw, &a.Params)
		return a, nil
	})
	if err != nil {
		return nil, nil, err
	}
	var next *time.Time
	if len(out) > limit {
		out = out[:limit]
		next = &out[limit-1].CreatedAt
	}
	return out, next, nil
}

// ── Raised from sign-ins ─────────────────────────────────────────────────

// signInAlerts looks at a sign-in just logged: many failures for one
// account, or an admin signing in from a country they haven't used before.
func (s *Store) signInAlerts(ctx context.Context, e SignIn) {
	u := e.User
	if u == nil || u.IsSupport() || e.Method == SignInSupport {
		return
	}
	if !e.Success {
		var n int
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM sign_in_log WHERE user_id = $1 AND NOT success
			AND method <> 'app' AND created_at > now() - make_interval(secs => $2)`,
			u.ID, FailedSignInWindow.Seconds()).Scan(&n); err != nil || n < FailedSignInLimit {
			return
		}
		s.RaiseAlert(ctx, NewAlert{OrganisationID: u.OrganisationID, Kind: AlertFailedSignIns,
			Severity: AlertSeverityWarning, SubjectID: u.ID, SubjectName: u.Name,
			Params: map[string]any{"count": n, "minutes": int(FailedSignInWindow.Minutes())},
			Title:  "Many failed sign-ins for " + u.Name,
			Body: fmt.Sprintf("%d failed sign-in attempts for %s (%s) in the last %d minutes.", n, u.Name, u.Email,
				int(FailedSignInWindow.Minutes())),
			DedupeFor: time.Hour})
		return
	}
	country := NormaliseCountry(e.Country)
	if country == "" || u.Role != "global_admin" || e.Method == SignInApp {
		return
	}
	var had bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_countries WHERE user_id = $1)`, u.ID).Scan(&had)
	tag, err := s.DB.Exec(ctx, `INSERT INTO user_countries (user_id, country) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		u.ID, country)
	if err != nil || tag.RowsAffected() == 0 || !had {
		return // known country, or the first one we've seen for them
	}
	s.RaiseAlert(ctx, NewAlert{OrganisationID: u.OrganisationID, Kind: AlertNewCountry,
		Severity: AlertSeverityWarning, SubjectID: u.ID, SubjectName: u.Name,
		Params:    map[string]any{"country": country},
		Title:     u.Name + " signed in from a new country",
		Body:      fmt.Sprintf("%s (%s), a global admin, signed in from %s for the first time.", u.Name, u.Email, country),
		DedupeKey: AlertNewCountry + ":" + u.ID + ":" + country, DedupeFor: 24 * time.Hour})
}

// NormaliseCountry: an ISO 3166 code from Cloudflare's CF-IPCountry, or "".
// XX (unknown) and T1 (Tor) say nothing about where they are.
func NormaliseCountry(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 2 || v == "XX" || v == "T1" {
		return ""
	}
	for _, c := range v {
		if c < 'A' || c > 'Z' {
			return ""
		}
	}
	return v
}

// ── Sign-in log reviewed ─────────────────────────────────────────────────

func (s *Store) SignInLogReviewedAt(ctx context.Context, orgID string) (*time.Time, error) {
	var t *time.Time
	err := s.DB.QueryRow(ctx, `SELECT sign_in_log_reviewed_at FROM organisations WHERE id = $1`, orgID).Scan(&t)
	return t, notFound(err)
}

func (s *Store) MarkSignInLogReviewed(ctx context.Context, orgID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE organisations SET sign_in_log_reviewed_at = now() WHERE id = $1`, orgID)
	return err
}
