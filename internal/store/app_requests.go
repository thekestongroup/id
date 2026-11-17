package store

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── App requests ─────────────────────────────────────────────────────────
//
// Someone asks their organisation's admins for an app they can't use yet:
// one that's Disabled for them, or a Keston product they have no licence
// for. Each request has a reason; there's one pending request per person per
// app, and a limit on how many a person can make in a day. Admins approve
// (adding the person to the app's "Approved requests" access rule and, if
// needed, assigning a licence within the organisation's seats) or decline
// (with an optional message). Everything is audited, and both sides are
// notified.

const (
	RequestPending   = "pending"
	RequestApproved  = "approved"
	RequestDeclined  = "declined"
	RequestCancelled = "cancelled"

	// MaxReasonLength is the longest reason, in characters.
	MaxReasonLength = 500
	// RequestsPerDay is how many requests one person can make in 24 hours.
	RequestsPerDay = 5
	// ApprovedRulesName is the access rule approvals add people to.
	ApprovedRulesName = "Approved requests"

	kestonAdminClient = "admin"
)

var (
	// The organisation has turned requests off.
	ErrRequestsOff = errors.New("requests are off")
	// Not an app they can ask for (unknown, another organisation's, turned off for requests).
	ErrNotRequestable = errors.New("can't be requested")
	// They can already use the app.
	ErrAlreadyHasAccess = errors.New("already has access")
	// A reason is needed, up to MaxReasonLength.
	ErrReasonInvalid = errors.New("reason needed")
	// Too many requests today.
	ErrRateLimited = errors.New("too many requests")
	// Already decided or cancelled.
	ErrNotPending = errors.New("not pending")
	// The person has gone (deleted, disabled or moved).
	ErrRequesterGone = errors.New("requester unavailable")
)

// AppRequest is one request, for the person's own list and for admins.
type AppRequest struct {
	ID              string     `json:"id"`
	UserID          string     `json:"userId"`
	UserName        string     `json:"userName"`
	UserEmail       string     `json:"userEmail"`
	ClientID        string     `json:"clientId"`
	AppName         string     `json:"appName"`
	Reason          string     `json:"reason"`
	Status          string     `json:"status"`
	DecisionMessage string     `json:"decisionMessage"`
	DecidedByName   string     `json:"decidedByName"`
	DecidedAt       *time.Time `json:"decidedAt,omitempty"`
	AddedToRule     bool       `json:"addedToRule"`
	LicenceAssigned bool       `json:"licenceAssigned"`
	// The requester has seen how it went.
	Seen      bool      `json:"seen"`
	CreatedAt time.Time `json:"createdAt"`
	// Pending only, for admins: what approving would do.
	Plan *RequestPlan `json:"plan,omitempty"`
}

// RequestPlan: what approving a request will do.
type RequestPlan struct {
	// Add them to the app's "Approved requests" rule (it's turned off for them).
	AddToRule bool `json:"addToRule"`
	// Assign a licence for the product (they have none).
	AssignLicence bool `json:"assignLicence"`
	// With a licence to assign: seats left (nil: unlimited), and whether there are none.
	SeatsLeft *int `json:"seatsLeft"`
	NoSeats   bool `json:"noSeats"`
	// Nothing needed: they can use it already (e.g. changed since).
	AlreadyAccess bool `json:"alreadyAccess"`
}

const requestColumns = `r.id::text, r.user_id::text, u.name, u.email, r.client_id, c.name, r.reason, r.status,
	r.decision_message, r.decided_by_name, r.decided_at, r.added_to_rule, r.licence_assigned,
	(r.seen_at IS NOT NULL), r.created_at`

const requestFrom = ` FROM app_requests r JOIN users u ON u.id = r.user_id JOIN clients c ON c.id = r.client_id`

func scanRequest(r pgx.CollectableRow) (AppRequest, error) {
	var q AppRequest
	err := r.Scan(&q.ID, &q.UserID, &q.UserName, &q.UserEmail, &q.ClientID, &q.AppName, &q.Reason, &q.Status,
		&q.DecisionMessage, &q.DecidedByName, &q.DecidedAt, &q.AddedToRule, &q.LicenceAssigned, &q.Seen, &q.CreatedAt)
	return q, err
}

func (s *Store) appRequests(ctx context.Context, where string, args ...any) ([]AppRequest, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+requestColumns+requestFrom+` WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanRequest)
}

// ── Settings ─────────────────────────────────────────────────────────────

// RequestSettings: whether people can request apps, and the apps they can't.
type RequestSettings struct {
	Enabled  bool     `json:"enabled"`
	Excluded []string `json:"excluded"`
}

func (s *Store) RequestSettings(ctx context.Context, orgID string) (RequestSettings, error) {
	out := RequestSettings{Enabled: true, Excluded: []string{}}
	err := s.DB.QueryRow(ctx, `SELECT enabled FROM app_request_settings WHERE organisation_id = $1`, orgID).Scan(&out.Enabled)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	rows, err := s.DB.Query(ctx, `SELECT client_id FROM app_request_exclusions WHERE organisation_id = $1 ORDER BY client_id`, orgID)
	if err != nil {
		return out, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if len(ids) > 0 {
		out.Excluded = ids
	}
	return out, err
}

// SetRequestSettings saves them. Excluded apps must be ones the organisation
// can use (ErrNotFound otherwise). It returns what changed ("" if nothing).
func (s *Store) SetRequestSettings(ctx context.Context, orgID string, enabled bool, excluded []string) (string, error) {
	before, err := s.RequestSettings(ctx, orgID)
	if err != nil {
		return "", err
	}
	apps, err := s.ClientsFor(ctx, orgID)
	if err != nil {
		return "", err
	}
	names := map[string]string{}
	for _, c := range apps {
		names[c.ID] = c.Name
	}
	clean := []string{}
	for _, id := range excluded {
		if _, ok := names[id]; !ok {
			return "", ErrNotFound
		}
		if !slices.Contains(clean, id) {
			clean = append(clean, id)
		}
	}
	slices.Sort(clean)
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO app_request_settings (organisation_id, enabled) VALUES ($1, $2)
		ON CONFLICT (organisation_id) DO UPDATE SET enabled = $2, updated_at = now()`, orgID, enabled); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_request_exclusions WHERE organisation_id = $1`, orgID); err != nil {
		return "", err
	}
	if len(clean) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO app_request_exclusions (organisation_id, client_id)
			SELECT $1, unnest($2::text[])`, orgID, clean); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	var parts []string
	if before.Enabled != enabled {
		if enabled {
			parts = append(parts, "Let people request apps: off → on")
		} else {
			parts = append(parts, "Let people request apps: on → off")
		}
	}
	for _, id := range clean {
		if !slices.Contains(before.Excluded, id) {
			parts = append(parts, names[id]+" can't be requested")
		}
	}
	for _, id := range before.Excluded {
		if !slices.Contains(clean, id) {
			n := names[id]
			if n == "" {
				n = id
			}
			parts = append(parts, n+" can be requested")
		}
	}
	return strings.Join(parts, ". "), nil
}

// ── What someone can request ─────────────────────────────────────────────

// appBlock: why someone can't use an app now: "" (they can), "licence" (a
// Keston product they have no licence for) or "disabled" (their organisation
// has turned it off for them).
func (s *Store) appBlock(ctx context.Context, u *User, c *Client, ip string) (string, error) {
	if ok, err := s.Licensed(ctx, u, c.ID); err != nil {
		return "", err
	} else if !ok {
		return "licence", nil
	}
	eff, err := s.EffectiveAppsFrom(ctx, u, ip)
	if err != nil {
		return "", err
	}
	if eff[c.ID] == AppDisabled {
		return "disabled", nil
	}
	return "", nil
}

// RequestableApps: the apps their organisation has that they can't use yet
// and may ask for. Empty when requests are off.
func (s *Store) RequestableApps(ctx context.Context, u *User, ip string) ([]Client, error) {
	if u.IsSupport() {
		return nil, nil
	}
	set, err := s.RequestSettings(ctx, u.OrganisationID)
	if err != nil || !set.Enabled {
		return nil, err
	}
	all, err := s.ClientsFor(ctx, u.OrganisationID)
	if err != nil {
		return nil, err
	}
	out := []Client{}
	for i := range all {
		c := all[i]
		if c.ID == kestonAdminClient || slices.Contains(set.Excluded, c.ID) {
			continue
		}
		if block, err := s.appBlock(ctx, u, &c, ip); err != nil {
			return nil, err
		} else if block != "" {
			out = append(out, c)
		}
	}
	return out, nil
}

// CanRequest: whether they can ask for this app now (what the sign-in error
// page checks before offering "Request access").
func (s *Store) CanRequest(ctx context.Context, u *User, clientID, ip string) bool {
	list, err := s.RequestableApps(ctx, u, ip)
	return err == nil && slices.ContainsFunc(list, func(c Client) bool { return c.ID == clientID })
}

// ── Making and cancelling requests ───────────────────────────────────────

// CreateAppRequest records a request, tells the organisation's admins and
// audits it. ip is where they asked from (for apps' IP rules and the log).
func (s *Store) CreateAppRequest(ctx context.Context, u *User, clientID, reason, ip string) (*AppRequest, error) {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n == 0 || n > MaxReasonLength {
		return nil, ErrReasonInvalid
	}
	set, err := s.RequestSettings(ctx, u.OrganisationID)
	if err != nil {
		return nil, err
	}
	if !set.Enabled || u.IsSupport() {
		return nil, ErrRequestsOff
	}
	app, err := s.ClientByID(ctx, clientID)
	if err != nil || app.RetiredAt != nil || clientID == kestonAdminClient ||
		(app.OrganisationID != nil && *app.OrganisationID != u.OrganisationID) || slices.Contains(set.Excluded, clientID) {
		return nil, ErrNotRequestable
	}
	block, err := s.appBlock(ctx, u, app, ip)
	if err != nil {
		return nil, err
	}
	if block == "" {
		return nil, ErrAlreadyHasAccess
	}

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Serialise a person's requests so the limit can't be raced past.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "app_requests:"+u.ID); err != nil {
		return nil, err
	}
	var pending bool
	var recent int
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM app_requests WHERE user_id = $1 AND client_id = $2 AND status = 'pending'),
		(SELECT count(*) FROM app_requests WHERE user_id = $1 AND created_at > now() - interval '24 hours')`,
		u.ID, clientID).Scan(&pending, &recent); err != nil {
		return nil, err
	}
	if pending {
		return nil, ErrPending
	}
	if recent >= RequestsPerDay {
		return nil, ErrRateLimited
	}
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO app_requests (organisation_id, user_id, client_id, reason)
		VALUES ($1, $2, $3, $4) RETURNING id::text`, u.OrganisationID, u.ID, clientID, reason).Scan(&id); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, ErrPending
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	req, err := s.AppRequestByID(ctx, u.OrganisationID, id)
	if err != nil {
		return nil, err
	}
	s.Audit(ctx, AuditEntry{OrganisationID: u.OrganisationID, Actor: u, Action: ActionAppRequested,
		TargetType: TargetApp, TargetID: app.ID, TargetName: app.Name, Summary: u.Name + " asked for access: " + reason, IP: ip})
	if admins, err := s.requestManagers(ctx, u.OrganisationID); err == nil {
		admins = slices.DeleteFunc(admins, func(id string) bool { return id == u.ID })
		_ = s.Notify(ctx, admins, "info", u.Name+" asked for "+app.Name, reason, "/app-requests")
	}
	return req, nil
}

// requestManagers: who decides requests: global admins and people who can
// set app access or assign licences.
func (s *Store) requestManagers(ctx context.Context, orgID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text FROM users WHERE organisation_id = $1 AND role = 'global_admin'
		AND status = 'active' AND support_for IS NULL`, orgID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	perms, err := s.PermissionsInOrganisation(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for id, p := range perms {
		if (p.Has(PermApps) || p.Has(PermLicences)) && !slices.Contains(out, id) {
			var active bool
			if err := s.DB.QueryRow(ctx, `SELECT status = 'active' AND support_for IS NULL FROM users
				WHERE id = $1 AND organisation_id = $2`, id, orgID).Scan(&active); err == nil && active {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

// AppRequestByID: one request in an organisation (ErrNotFound if it isn't
// theirs).
func (s *Store) AppRequestByID(ctx context.Context, orgID, id string) (*AppRequest, error) {
	if !IsUUID(id) {
		return nil, ErrNotFound
	}
	list, err := s.appRequests(ctx, `r.organisation_id = $1 AND r.id = $2`, orgID, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// MyAppRequests: someone's own requests, newest first.
func (s *Store) MyAppRequests(ctx context.Context, userID string) ([]AppRequest, error) {
	return s.appRequests(ctx, `r.user_id = $1 ORDER BY r.created_at DESC LIMIT 100`, userID)
}

// CancelAppRequest withdraws their own pending request.
func (s *Store) CancelAppRequest(ctx context.Context, u *User, id, ip string) error {
	if !IsUUID(id) {
		return ErrNotFound
	}
	var clientID, name string
	err := s.DB.QueryRow(ctx, `UPDATE app_requests r SET status = 'cancelled', decided_at = now(), seen_at = now()
		FROM clients c WHERE c.id = r.client_id AND r.id = $1 AND r.user_id = $2 AND r.status = 'pending'
		RETURNING r.client_id, c.name`, id, u.ID).Scan(&clientID, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err == nil {
		s.Audit(ctx, AuditEntry{OrganisationID: u.OrganisationID, Actor: u, Action: ActionAppRequestCancelled,
			TargetType: TargetApp, TargetID: clientID, TargetName: name, Summary: u.Name + " withdrew their request", IP: ip})
	}
	return err
}

// MarkAppRequestsSeen: they've seen how their requests went.
func (s *Store) MarkAppRequestsSeen(ctx context.Context, userID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE app_requests SET seen_at = now() WHERE user_id = $1 AND seen_at IS NULL
		AND status <> 'pending'`, userID)
	return err
}

// ── Admins ───────────────────────────────────────────────────────────────

// RequestFilter narrows an organisation's list. Empty fields don't filter.
type RequestFilter struct {
	Status   string // pending, approved, declined (cancelled are never listed)
	ClientID string
	Query    string // name or email of the requester
}

// AppRequestsOf: an organisation's requests, pending first then newest.
func (s *Store) AppRequestsOf(ctx context.Context, orgID string, f RequestFilter) ([]AppRequest, error) {
	where := `r.organisation_id = $1 AND r.status <> 'cancelled'`
	args := []any{orgID}
	if f.Status != "" {
		args = append(args, f.Status)
		where += ` AND r.status = $` + itoa(len(args))
	}
	if f.ClientID != "" {
		args = append(args, f.ClientID)
		where += ` AND r.client_id = $` + itoa(len(args))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+escapeLike(strings.ToLower(q))+"%")
		where += ` AND (lower(u.name) LIKE $` + itoa(len(args)) + ` OR lower(u.email) LIKE $` + itoa(len(args)) + `)`
	}
	list, err := s.appRequests(ctx, where+` ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Status == RequestPending {
			if p, err := s.PlanFor(ctx, &list[i]); err == nil {
				list[i].Plan = p
			}
		}
	}
	return list, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// PendingAppRequestCount: for the badge.
func (s *Store) PendingAppRequestCount(ctx context.Context, orgID string) (int, error) {
	var n int
	err := s.DB.QueryRow(ctx, `SELECT count(*) FROM app_requests WHERE organisation_id = $1 AND status = 'pending'`, orgID).Scan(&n)
	return n, err
}

// modeIgnoringLicence: the person's access to the app from the organisation's
// default and rules alone (licences aside).
func (s *Store) modeIgnoringLicence(ctx context.Context, u *User, c *Client) (string, error) {
	def := ""
	if c.Builtin {
		def = AppForced
	}
	policies, err := s.AppPolicies(ctx, u.OrganisationID)
	if err != nil {
		return "", err
	}
	for _, p := range policies {
		if p.ClientID == c.ID {
			def = p.Mode
		}
	}
	rules, err := s.AppRules(ctx, u.OrganisationID, c.ID)
	if err != nil {
		return "", err
	}
	groups, err := s.GroupIDsForUser(ctx, u.ID)
	if err != nil {
		return "", err
	}
	return ResolveAppMode(def, rules, u.ID, groups, ""), nil
}

// PlanFor works out what approving would do now.
func (s *Store) PlanFor(ctx context.Context, req *AppRequest) (*RequestPlan, error) {
	u, err := s.UserByID(ctx, req.UserID)
	if err != nil {
		return nil, err
	}
	c, err := s.ClientByID(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	p := &RequestPlan{}
	licensed, err := s.Licensed(ctx, u, c.ID)
	if err != nil {
		return nil, err
	}
	mode, err := s.modeIgnoringLicence(ctx, u, c)
	if err != nil {
		return nil, err
	}
	p.AddToRule = mode == AppDisabled
	p.AssignLicence = !licensed
	p.AlreadyAccess = !p.AddToRule && !p.AssignLicence
	if p.AssignLicence {
		products, err := s.Products(ctx, u.OrganisationID)
		if err != nil {
			return nil, err
		}
		for _, pr := range products {
			if pr.ID == c.ID {
				p.SeatsLeft = pr.Available
				p.NoSeats = pr.Available != nil && *pr.Available == 0
			}
		}
	}
	return p, nil
}

// ApproveOptions: what approving does; nil means "whatever the plan says".
type ApproveOptions struct {
	AddToRule     *bool
	AssignLicence *bool
	Message       string
	IP            string
}

// ApproveAppRequest grants the request: assigns the licence first (it fails
// with a *NoSeatsError, changing nothing, if there are no seats left), then
// adds them to the app's "Approved requests" rule and records the decision.
func (s *Store) ApproveAppRequest(ctx context.Context, orgID, id string, by *User, o ApproveOptions) (*AppRequest, error) {
	req, err := s.AppRequestByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if req.Status != RequestPending {
		return nil, ErrNotPending
	}
	u, err := s.UserByID(ctx, req.UserID)
	if err != nil || u.OrganisationID != orgID || u.Status != "active" {
		return nil, ErrRequesterGone
	}
	plan, err := s.PlanFor(ctx, req)
	if err != nil {
		return nil, err
	}
	addRule, assign := plan.AddToRule, plan.AssignLicence
	if o.AddToRule != nil {
		addRule = *o.AddToRule && plan.AddToRule
	}
	if o.AssignLicence != nil {
		assign = *o.AssignLicence && plan.AssignLicence
	}
	if assign {
		have, err := s.Licences(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if _, _, err := s.SetLicences(ctx, u.ID, &by.ID, append(have, req.ClientID)); err != nil {
			return nil, err
		}
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Decide first: only one decision wins.
	tag, err := tx.Exec(ctx, `UPDATE app_requests SET status = 'approved', decision_message = $3, decided_by = $4,
		decided_by_name = $5, decided_at = now(), added_to_rule = $6, licence_assigned = $7
		WHERE id = $1 AND organisation_id = $2 AND status = 'pending'`, id, orgID, strings.TrimSpace(o.Message), by.ID, by.Name,
		addRule, assign)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotPending
	}
	if addRule {
		if _, err := tx.Exec(ctx, `INSERT INTO app_rules (organisation_id, client_id, name, position, enabled, mode, user_ids,
				approved_requests)
			VALUES ($1, $2, $3, coalesce((SELECT min(position) FROM app_rules WHERE organisation_id = $1 AND client_id = $2), 1) - 1,
				TRUE, 'enabled', ARRAY[$4]::uuid[], TRUE)
			ON CONFLICT (organisation_id, client_id) WHERE approved_requests DO UPDATE SET
				user_ids = (SELECT array_agg(DISTINCT x) FROM unnest(app_rules.user_ids || $4::uuid) x),
				enabled = TRUE, mode = 'enabled', updated_at = now()`,
			orgID, req.ClientID, ApprovedRulesName, u.ID); err != nil {
			return nil, err
		}
		// If they'd removed the app themselves, it comes back.
		if _, err := tx.Exec(ctx, `DELETE FROM removed_apps WHERE user_id = $1 AND client_id = $2`, u.ID, req.ClientID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	var did []string
	if addRule {
		did = append(did, "added to “"+ApprovedRulesName+"”")
	}
	if assign {
		did = append(did, "licence assigned")
	}
	summary := "Approved " + req.UserName + "’s request"
	if len(did) > 0 {
		summary += ": " + strings.Join(did, ", ")
	}
	s.Audit(ctx, AuditEntry{OrganisationID: orgID, Actor: by, Action: ActionAppRequestApproved, TargetType: TargetApp,
		TargetID: req.ClientID, TargetName: req.AppName, Summary: summary, IP: o.IP})
	body := "You can use " + req.AppName + " now."
	if m := strings.TrimSpace(o.Message); m != "" {
		body += " " + by.Name + ": " + m
	}
	_ = s.Notify(ctx, []string{u.ID}, "success", "Your request for "+req.AppName+" was approved", body, "/account/requests")
	return s.AppRequestByID(ctx, orgID, id)
}

// DeclineAppRequest turns the request down, with an optional message.
func (s *Store) DeclineAppRequest(ctx context.Context, orgID, id string, by *User, message, ip string) (*AppRequest, error) {
	req, err := s.AppRequestByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	message = strings.TrimSpace(message)
	tag, err := s.DB.Exec(ctx, `UPDATE app_requests SET status = 'declined', decision_message = $3, decided_by = $4,
		decided_by_name = $5, decided_at = now() WHERE id = $1 AND organisation_id = $2 AND status = 'pending'`,
		id, orgID, message, by.ID, by.Name)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotPending
	}
	summary := "Declined " + req.UserName + "’s request"
	if message != "" {
		summary += ": " + message
	}
	s.Audit(ctx, AuditEntry{OrganisationID: orgID, Actor: by, Action: ActionAppRequestDeclined, TargetType: TargetApp,
		TargetID: req.ClientID, TargetName: req.AppName, Summary: summary, IP: ip})
	body := "Your organisation's admins decided not to give you access for now."
	if message != "" {
		body = by.Name + ": " + message
	}
	_ = s.Notify(ctx, []string{req.UserID}, "warning", "Your request for "+req.AppName+" was declined", body, "/account/requests")
	return s.AppRequestByID(ctx, orgID, id)
}
