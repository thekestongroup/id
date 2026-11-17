package adminapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/store"
)

// ── Security defaults and Secure Score ───────────────────────────────────
//
// A checklist of recommended settings. Each item is done or not, has a
// weight, and either an Apply (it changes the real setting, through the same
// code as the setting's own page) or advice (Keston Admin links to where to
// fix it). The Secure Score is the share of the weights that are done, worked
// out here from the organisation's real settings, so the dashboard and the
// checklist always agree.

// Item IDs.
const (
	itemMFAEveryone   = "mfa_everyone"
	itemMFAAdmins     = "mfa_admins"
	itemPassword      = "password_policy"
	itemTwoAdmins     = "two_global_admins"
	itemAdminsMFA     = "admins_have_mfa"
	itemGuestsOff     = "guests_off"
	itemSignInReview  = "sign_in_log_reviewed"
	signInReviewEvery = 30 * 24 * time.Hour
)

// The password policy "at least Recommended": 12 characters and a number.
const (
	recommendedMinLength = 12
	recommendedMinDigits = 1
)

type secFacts struct {
	MFAMode string
	// Global admins who are active (not Keston support accounts), how many
	// MFA is required of, and how many have MFA set up (an app or a passkey).
	Admins, AdminsMFARequired, AdminsWithMFA int
	Policy                                   policy.Policy
	AllowGuests                              bool
	LogReviewedAt                            *time.Time
	Now                                      time.Time
}

type secItem struct {
	ID     string `json:"id"`
	Weight int    `json:"weight"`
	Done   bool   `json:"done"`
	// Apply changes the setting; otherwise it's advice (Link says where).
	CanApply bool `json:"canApply"`
	// Where Keston Admin sends people to fix it: users, sign-ins, mfa, password, guests.
	Link string `json:"link"`
	// Numbers for the text (admins without MFA…).
	Detail map[string]int `json:"detail,omitempty"`
	// Advice that can also be ticked off by hand (the sign-in log).
	CanMark bool `json:"canMark,omitempty"`
}

// evaluateSecurity: the checklist for these facts, in the order shown.
func evaluateSecurity(f secFacts) []secItem {
	everyone := f.MFAMode == store.MFARequired
	return []secItem{
		{ID: itemMFAEveryone, Weight: 25, Done: everyone, CanApply: true, Link: "mfa"},
		{ID: itemMFAAdmins, Weight: 15, Done: f.Admins > 0 && f.AdminsMFARequired == f.Admins, CanApply: true, Link: "mfa",
			Detail: map[string]int{"missing": f.Admins - f.AdminsMFARequired}},
		{ID: itemPassword, Weight: 15, Done: f.Policy.MinLength >= recommendedMinLength && f.Policy.MinDigits >= recommendedMinDigits,
			CanApply: true, Link: "password"},
		{ID: itemTwoAdmins, Weight: 10, Done: f.Admins >= 2, Link: "users", Detail: map[string]int{"admins": f.Admins}},
		{ID: itemAdminsMFA, Weight: 20, Done: f.Admins > 0 && f.AdminsWithMFA == f.Admins, Link: "users",
			Detail: map[string]int{"missing": f.Admins - f.AdminsWithMFA}},
		{ID: itemGuestsOff, Weight: 5, Done: !f.AllowGuests, CanApply: true, Link: "guests"},
		{ID: itemSignInReview, Weight: 10, Done: f.LogReviewedAt != nil && f.Now.Sub(*f.LogReviewedAt) < signInReviewEvery,
			Link: "sign-ins", CanMark: true},
	}
}

// secureScore: the percentage of the weights that are done (0–100).
func secureScore(items []secItem) int {
	total, done := 0, 0
	for _, it := range items {
		total += it.Weight
		if it.Done {
			done += it.Weight
		}
	}
	if total == 0 {
		return 0
	}
	return int(float64(done)/float64(total)*100 + 0.5)
}

// gatherFacts reads the settings the checklist is about.
func (a *API) gatherFacts(r *http.Request) (secFacts, error) {
	ctx := r.Context()
	org, err := a.store.OrganisationByID(ctx, organisation(r).ID) // fresh: apply changes it
	if err != nil {
		return secFacts{}, err
	}
	mfa, err := a.store.MFAPolicy(ctx, org.ID)
	if err != nil {
		return secFacts{}, err
	}
	reviewed, err := a.store.SignInLogReviewedAt(ctx, org.ID)
	if err != nil {
		return secFacts{}, err
	}
	admins, err := a.store.GlobalAdmins(ctx, org.ID)
	if err != nil {
		return secFacts{}, err
	}
	f := secFacts{MFAMode: mfa.Mode, Policy: org.PasswordPolicy, AllowGuests: org.AllowGuests, LogReviewedAt: reviewed,
		Now: time.Now()}
	for i := range admins {
		u := &admins[i]
		if u.IsSupport() {
			continue
		}
		f.Admins++
		st, err := a.store.SignInState(ctx, u, store.SignInContext{})
		if err != nil {
			return f, err
		}
		if st.MFARequired {
			f.AdminsMFARequired++
		}
		has := u.TOTPEnabled
		if !has {
			n, err := a.store.PasskeyCount(ctx, u.ID)
			if err != nil {
				return f, err
			}
			has = n > 0
		}
		if has {
			f.AdminsWithMFA++
		}
	}
	return f, nil
}

type securityState struct {
	// 0–100.
	Score  int        `json:"score"`
	Items  []secItem  `json:"items"`
	Done   int        `json:"done"`
	Total  int        `json:"total"`
	Review *time.Time `json:"signInLogReviewedAt"`
}

func (a *API) securityState(r *http.Request) (*securityState, error) {
	f, err := a.gatherFacts(r)
	if err != nil {
		return nil, err
	}
	items := evaluateSecurity(f)
	st := &securityState{Score: secureScore(items), Items: items, Total: len(items), Review: f.LogReviewedAt}
	for _, it := range items {
		if it.Done {
			st.Done++
		}
	}
	return st, nil
}

// GET …/security/defaults: the checklist and the Secure Score (the one place
// the score is worked out; the dashboard tile uses it too).
func (a *API) getSecurityDefaults(w http.ResponseWriter, r *http.Request) {
	st, err := a.securityState(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type applyResult struct {
	ID string `json:"id"`
	// applied, already (nothing to do), failed, not_applicable.
	Result string `json:"result"`
}

// POST …/security/defaults/apply {items: [ids]}: applies the recommended
// setting for each (the ones that can be applied and aren't done yet), each
// recorded in the audit log like the same change on its own page. Returns
// what happened to each, and the new checklist.
func (a *API) applySecurityDefaults(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []string `json:"items"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Items) == 0 || len(body.Items) > 20 {
		writeFieldError(w, "items", "Choose what to apply")
		return
	}
	before, err := a.securityState(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	results := []applyResult{}
	for _, id := range slices.Compact(slices.Clone(body.Items)) {
		var item *secItem
		for i := range before.Items {
			if before.Items[i].ID == id {
				item = &before.Items[i]
			}
		}
		switch {
		case item == nil || !item.CanApply:
			results = append(results, applyResult{id, "not_applicable"})
		case item.Done:
			results = append(results, applyResult{id, "already"})
		default:
			if err := a.applyItem(r, id); err != nil {
				slog.Error("security defaults", "item", id, "organisation", organisation(r).ID, "error", err)
				results = append(results, applyResult{id, "failed"})
				continue
			}
			results = append(results, applyResult{id, "applied"})
		}
	}
	// A change by an earlier item (the MFA mode) can settle a later one, so
	// the organisation in the request context is read again each time.
	st, err := a.securityState(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "state": st})
}

// adminsRuleName: the MFA rule "Require MFA for admins" adds.
const adminsRuleName = "Global admins"

func (a *API) applyItem(r *http.Request, id string) error {
	ctx := r.Context()
	org, err := a.store.OrganisationByID(ctx, organisation(r).ID)
	if err != nil {
		return err
	}
	// The same organisation the pages use, but up to date.
	r = r.WithContext(context.WithValue(ctx, orgKey, org))
	switch id {
	case itemMFAEveryone:
		mode := store.MFARequired
		return a.applyMFAPolicy(r, &mode, nil, nil)
	case itemMFAAdmins:
		return a.requireMFAForAdmins(r, org)
	case itemPassword:
		p := org.PasswordPolicy
		p.MinLength = max(p.MinLength, recommendedMinLength)
		p.MinDigits = max(p.MinDigits, recommendedMinDigits)
		return a.applyPasswordPolicy(r, p.Normalise())
	case itemGuestsOff:
		return a.applyAllowGuests(r, false)
	}
	return fmt.Errorf("no way to apply %q", id)
}

// requireMFAForAdmins: custom rules, with a first rule requiring MFA of the
// organisation's current global admins (made, or brought up to date, here).
func (a *API) requireMFAForAdmins(r *http.Request, org *store.Organisation) error {
	ctx := r.Context()
	mfa, err := a.store.MFAPolicy(ctx, org.ID)
	if err != nil {
		return err
	}
	if mfa.Mode == store.MFARequired {
		return nil // everyone, admins too
	}
	if mfa.Mode == store.MFAOff {
		mode := store.MFACustom
		if err := a.applyMFAPolicy(r, &mode, nil, nil); err != nil {
			return err
		}
	}
	admins, err := a.store.GlobalAdmins(ctx, org.ID)
	if err != nil {
		return err
	}
	ids := []string{}
	for _, u := range admins {
		if !u.IsSupport() {
			ids = append(ids, u.ID)
		}
	}
	rules, err := a.store.MFARules(ctx, org.ID)
	if err != nil {
		return err
	}
	rule := store.MFARule{Name: adminsRuleName, Enabled: true, Require: true, Users: ids,
		Groups: []string{}, Apps: []string{}, IPRanges: []string{}}
	verb := "Rule added: "
	if i := slices.IndexFunc(rules, func(x store.MFARule) bool { return x.Name == adminsRuleName }); i >= 0 {
		rule.ID, verb = rules[i].ID, "Rule changed: "
	}
	saved, err := a.store.SaveMFARule(ctx, org.ID, rule)
	if err != nil {
		return err
	}
	// First, so no earlier rule can exempt them.
	order := []string{saved.ID}
	for _, x := range rules {
		if x.ID != saved.ID {
			order = append(order, x.ID)
		}
	}
	if len(order) > 1 || rule.ID == "" {
		if err := a.store.OrderMFARules(ctx, org.ID, order); err != nil {
			return err
		}
	}
	a.audit(r, store.ActionMFAPolicy, aboutOrg(org), verb+saved.Name)
	return nil
}

// POST …/security/defaults/sign-in-review: "I've reviewed the sign-in log".
func (a *API) markSignInsReviewed(w http.ResponseWriter, r *http.Request) {
	org := organisation(r)
	if err := a.store.MarkSignInLogReviewed(r.Context(), org.ID); err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionSettings, aboutOrg(org), "Sign-in log marked as reviewed")
	a.getSecurityDefaults(w, r)
}

// ── Alerts ───────────────────────────────────────────────────────────────

// alert raises a security alert in the organisation in the URL.
func (a *API) alert(r *http.Request, n store.NewAlert) {
	n.OrganisationID = organisation(r).ID
	a.store.RaiseAlert(r.Context(), n)
}

func actorName(r *http.Request) string {
	if u := caller(r); u != nil {
		return u.Name
	}
	return "Someone"
}

// alertAdminAdded: a new global admin or TKG Admin.
func (a *API) alertAdminAdded(r *http.Request, u *store.User) {
	switch {
	case u.PlatformAdmin:
		a.alert(r, store.NewAlert{Kind: store.AlertAdminAdded, Severity: store.AlertSeverityHigh, SubjectID: u.ID,
			SubjectName: u.Name, Params: map[string]any{"by": actorName(r), "role": "tkg_admin"},
			Title: "New TKG Admin: " + u.Name, Body: actorName(r) + " made " + u.Name + " a TKG Admin.",
			DedupeKey: store.AlertAdminAdded + ":" + u.ID, DedupeFor: 10 * time.Minute})
	case u.Role == "global_admin":
		a.alert(r, store.NewAlert{Kind: store.AlertAdminAdded, Severity: store.AlertSeverityHigh, SubjectID: u.ID,
			SubjectName: u.Name, Params: map[string]any{"by": actorName(r), "role": "global_admin"},
			Title: "New global admin: " + u.Name, Body: actorName(r) + " made " + u.Name + " a global admin.",
			DedupeKey: store.AlertAdminAdded + ":" + u.ID, DedupeFor: 10 * time.Minute})
	}
}

// GET …/security/alerts?kind=&severity=&from=&to=&before=&limit=: recent
// security alerts, newest first.
func (a *API) listSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AlertFilter{OrganisationID: organisation(r).ID, Kinds: listParam(q, "kind"),
		Severities: listParam(q, "severity")}
	for _, k := range f.Kinds {
		if !slices.Contains(store.AlertKinds, k) {
			writeFieldError(w, "kind", "Choose from the kinds of alert")
			return
		}
	}
	for _, s := range f.Severities {
		if !slices.Contains([]string{store.AlertSeverityInfo, store.AlertSeverityWarning, store.AlertSeverityHigh}, s) {
			writeFieldError(w, "severity", "Choose from the severities")
			return
		}
	}
	for name, dst := range map[string]**time.Time{"from": &f.From, "to": &f.To, "before": &f.Before} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				writeFieldError(w, name, "Enter a date and time")
				return
			}
			*dst = &t
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeFieldError(w, "limit", "Enter a number")
			return
		}
		f.Limit = n
	}
	alerts, next, err := a.store.SecurityAlerts(r.Context(), f)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if alerts == nil {
		alerts = []store.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": alerts, "next": next})
}
