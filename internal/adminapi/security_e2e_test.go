//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/store"
)

type defaultsOut struct {
	Score   int
	Items   []secItem
	State   *defaultsOut
	Results []applyResult
}

func (e *env) defaults(as *store.User) defaultsOut {
	e.t.Helper()
	code, raw := e.do(as, http.MethodGet, "/security/defaults", nil)
	if code != http.StatusOK {
		e.t.Fatalf("defaults: %d %s", code, raw)
	}
	var out defaultsOut
	_ = json.Unmarshal(raw, &out)
	return out
}

func (o defaultsOut) item(id string) secItem {
	for _, it := range o.Items {
		if it.ID == id {
			return it
		}
	}
	return secItem{}
}

func (e *env) alerts(as *store.User, query string) []store.Alert {
	e.t.Helper()
	code, raw := e.do(as, http.MethodGet, "/security/alerts"+query, nil)
	if code != http.StatusOK {
		e.t.Fatalf("alerts: %d %s", code, raw)
	}
	var out struct{ Items []store.Alert }
	_ = json.Unmarshal(raw, &out)
	return out.Items
}

func TestApplySecurityDefaults(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()

	// A new organisation: MFA required for everyone, nothing else done.
	d := e.defaults(admin)
	if !d.item(itemMFAEveryone).Done || d.item(itemPassword).Done || d.item(itemGuestsOff).Done != true {
		t.Fatalf("starting point: %+v", d.Items)
	}
	start := d.Score

	// Make it worse, then apply: the real settings change, and are audited.
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET allow_guests = TRUE, mfa_mode = 'off' WHERE id = $1`, e.org.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.defaults(admin).Score; got >= start {
		t.Errorf("worse settings, score %d → %d", start, got)
	}
	code, raw := e.do(admin, http.MethodPost, "/security/defaults/apply",
		map[string]any{"items": []string{itemMFAEveryone, itemPassword, itemGuestsOff, itemTwoAdmins, "nonsense"}})
	var out defaultsOut
	_ = json.Unmarshal(raw, &out)
	if code != http.StatusOK {
		t.Fatalf("apply: %d %s", code, raw)
	}
	got := map[string]string{}
	for _, r := range out.Results {
		got[r.ID] = r.Result
	}
	if got[itemMFAEveryone] != "applied" || got[itemPassword] != "applied" || got[itemGuestsOff] != "applied" ||
		got[itemTwoAdmins] != "not_applicable" || got["nonsense"] != "not_applicable" {
		t.Errorf("results: %v", got)
	}
	org, _ := e.st.OrganisationByID(ctx, e.org.ID)
	mfa, _ := e.st.MFAPolicy(ctx, e.org.ID)
	if mfa.Mode != store.MFARequired || org.AllowGuests || org.PasswordPolicy.MinLength < 12 || org.PasswordPolicy.MinDigits < 1 {
		t.Errorf("not applied: %+v %+v", mfa, org)
	}
	// Applying again does nothing.
	_, raw = e.do(admin, http.MethodPost, "/security/defaults/apply", map[string]any{"items": []string{itemPassword}})
	_ = json.Unmarshal(raw, &out)
	if out.Results[0].Result != "already" {
		t.Errorf("again: %v", out.Results)
	}
	// Audited, as the same actions as the normal pages.
	recs, _, _ := e.st.AuditLog(ctx, store.LogFilter{OrganisationID: e.org.ID, Limit: 20})
	seen := map[string]bool{}
	for _, r := range recs {
		seen[r.Action] = true
	}
	for _, a := range []string{store.ActionMFAPolicy, store.ActionPasswordPolicy, store.ActionGuestSetting} {
		if !seen[a] {
			t.Errorf("no audit entry %s", a)
		}
	}

	// Needs the Security permission.
	helper := e.user("helper", "member")
	g := e.group("Helpdesk", store.PermViewUsers)
	_ = e.st.AddGroupMember(ctx, g.ID, helper.ID)
	if code, _ := e.do(helper, http.MethodGet, "/security/defaults", nil); code != http.StatusForbidden {
		t.Errorf("without permission: %d", code)
	}
}

func TestRequireMFAForAdmins(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	_, _ = e.st.DB.Exec(ctx, `UPDATE organisations SET mfa_mode = 'off' WHERE id = $1`, e.org.ID)
	if e.defaults(admin).item(itemMFAAdmins).Done {
		t.Fatal("MFA is off")
	}
	// An earlier rule that would exempt them must not matter.
	if _, err := e.st.SaveMFARule(ctx, e.org.ID, store.MFARule{Name: "Exempt", Enabled: true, Require: false,
		Users: []string{}, Groups: []string{}, Apps: []string{}, IPRanges: []string{}}); err != nil {
		t.Fatal(err)
	}
	_, raw := e.do(admin, http.MethodPost, "/security/defaults/apply", map[string]any{"items": []string{itemMFAAdmins}})
	var out defaultsOut
	_ = json.Unmarshal(raw, &out)
	if out.Results[0].Result != "applied" || out.State == nil || !out.State.item(itemMFAAdmins).Done {
		t.Fatalf("apply: %s", raw)
	}
	// Members aren't asked for it.
	member := e.user("member", "member")
	if st, _ := e.st.SignInState(ctx, member, store.SignInContext{}); st.MFARequired {
		t.Error("members shouldn't need MFA")
	}
	// A second admin: the item is not done until it's applied again.
	e.user("second", "global_admin")
	if e.defaults(admin).item(itemMFAAdmins).Done {
		t.Error("new admin isn't covered yet")
	}
	e.do(admin, http.MethodPost, "/security/defaults/apply", map[string]any{"items": []string{itemMFAAdmins}})
	if !e.defaults(admin).item(itemMFAAdmins).Done {
		t.Error("not done after applying again")
	}
	rules, _ := e.st.MFARules(ctx, e.org.ID)
	if len(rules) != 2 || rules[0].Name != adminsRuleName {
		t.Errorf("rules: %+v", rules)
	}
}

func TestSecurityAlertsFromChanges(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	second := e.user("second", "global_admin")
	member := e.user("member", "member")

	// MFA turned off, and again straight away: one alert.
	for i := 0; i < 2; i++ {
		e.do(admin, http.MethodPut, "/mfa-policy", map[string]any{"mode": "off"})
		e.do(admin, http.MethodPut, "/mfa-policy", map[string]any{"mode": "required"})
	}
	// Password policy weakened.
	e.do(admin, http.MethodPut, "/password-policy", policy.Policy{MinLength: 14})
	e.do(admin, http.MethodPut, "/password-policy", policy.Policy{MinLength: 10})
	// Stricter: no alert.
	e.do(admin, http.MethodPut, "/password-policy", policy.Policy{MinLength: 16})
	// A new global admin, by creating and by promoting; an admin role.
	e.do(admin, http.MethodPost, "/users", map[string]any{"name": "New Admin", "username": "newadmin",
		"password": "correct-horse-battery-1", "role": "global_admin"})
	e.do(admin, http.MethodPatch, "/users/"+member.ID, map[string]any{"role": "global_admin"})
	e.do(admin, http.MethodPut, "/users/"+e.user("helper", "member").ID+"/roles", map[string]any{"roles": []string{store.AdminRoles[0].ID}})

	count := map[string]int{}
	for _, a := range e.alerts(admin, "") {
		count[a.Kind]++
	}
	if count[store.AlertMFAOff] != 1 || count[store.AlertPasswordWeaker] != 1 || count[store.AlertAdminAdded] != 2 ||
		count[store.AlertAdminRole] != 1 {
		t.Errorf("alerts: %v", count)
	}
	if got := e.alerts(admin, "?kind=mfa_off"); len(got) != 1 {
		t.Errorf("filter by kind: %d", len(got))
	}
	if got := e.alerts(admin, "?severity=critical"); len(got) != 3 { // mfa off, 2 admins
		t.Errorf("filter by severity: %d", len(got))
	}
	if code, _ := e.do(admin, http.MethodGet, "/security/alerts?kind=bogus", nil); code != http.StatusUnprocessableEntity {
		t.Errorf("bad kind: %d", code)
	}

	// Delivered in app, to the organisation's global admins, not to members.
	for _, u := range []*store.User{admin, second} {
		ns, _ := e.st.Notifications(ctx, u.ID)
		if len(ns) < 5 {
			t.Errorf("%s got %d notifications", u.Name, len(ns))
		}
	}
	other := e.user("plain", "member")
	g := e.group("Helpdesk", store.PermViewUsers)
	_ = e.st.AddGroupMember(ctx, g.ID, other.ID)
	if ns, _ := e.st.Notifications(ctx, other.ID); len(ns) != 0 {
		t.Errorf("a member was notified: %d", len(ns))
	}
	// Alerts need View reports.
	if code, _ := e.do(other, http.MethodGet, "/security/alerts", nil); code != http.StatusForbidden {
		t.Errorf("alerts without permission: %d", code)
	}
}

func TestSignInAlerts(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	victim := e.user("victim", "member")

	// Nine failures: nothing. The tenth: one alert; more: still one.
	for i := 1; i <= 12; i++ {
		e.st.LogSignIn(ctx, store.SignIn{User: victim, Method: store.SignInPassword, Reason: store.ReasonWrongPassword})
		if i == 9 && len(e.alerts(admin, "?kind=failed_sign_ins")) != 0 {
			t.Fatal("alert too early")
		}
	}
	if got := e.alerts(admin, "?kind=failed_sign_ins"); len(got) != 1 || got[0].SubjectName != "victim" {
		t.Fatalf("failed sign-ins: %+v", got)
	}

	// Five wrong passwords in a row lock the account: one alert.
	for i := 0; i < 7; i++ {
		_ = e.st.RecordLogin(ctx, victim.ID, false)
	}
	if got := e.alerts(admin, "?kind=account_locked"); len(got) != 1 {
		t.Errorf("locked: %d", len(got))
	}

	// A new country for an admin: the first is learned quietly, a known one
	// is fine, a new one raises an alert once. Members don't.
	in := func(u *store.User, country string) {
		e.st.LogSignIn(ctx, store.SignIn{User: u, Method: store.SignInPassword, Success: true, Country: country})
	}
	in(admin, "GB")
	in(admin, "gb")
	in(admin, "XX")
	in(admin, "")
	in(victim, "GB")
	in(victim, "FR")
	if got := e.alerts(admin, "?kind=new_country"); len(got) != 0 {
		t.Fatalf("no new country yet: %d", len(got))
	}
	in(admin, "FR")
	in(admin, "FR")
	got := e.alerts(admin, "?kind=new_country")
	if len(got) != 1 || got[0].Params["country"] != "FR" {
		t.Fatalf("new country: %+v", got)
	}
	// Notified in the bell with a link to the alerts page.
	ns, _ := e.st.Notifications(ctx, admin.ID)
	found := false
	for _, n := range ns {
		if n.Title == "Admin Ada signed in from a new country" || n.Link == "/organisations/"+e.org.ID+"/security/alerts" {
			found = true
		}
	}
	if !found {
		t.Errorf("no notification: %+v", ns)
	}
}

// A second sink gets the same alerts (how email will be added).
type recordSink struct{ got *[]store.Alert }

func (s recordSink) Deliver(_ context.Context, _ *store.Store, a store.Alert, _ []store.User) error {
	*s.got = append(*s.got, a)
	return nil
}

func TestAlertSinks(t *testing.T) {
	e := setup(t)
	var got []store.Alert
	store.RegisterAlertSink(recordSink{&got})
	ok := e.st.RaiseAlert(context.Background(), store.NewAlert{OrganisationID: e.org.ID, Kind: store.AlertMFAOff,
		Title: "x", DedupeKey: "k", DedupeFor: time.Minute})
	dup := e.st.RaiseAlert(context.Background(), store.NewAlert{OrganisationID: e.org.ID, Kind: store.AlertMFAOff,
		Title: "x", DedupeKey: "k", DedupeFor: time.Minute})
	if !ok || dup || len(got) != 1 {
		t.Errorf("sink: raised=%v duplicate=%v delivered=%d", ok, dup, len(got))
	}
}
