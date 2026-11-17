//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

type reqOut struct {
	ID, Status, DecisionMessage, ClientID string
	AddedToRule, LicenceAssigned          bool
	Plan                                  *store.RequestPlan
}

func (e *env) requests(as *store.User, query string) []reqOut {
	e.t.Helper()
	code, raw := e.do(as, http.MethodGet, "/app-requests"+query, nil)
	var out []reqOut
	if code != http.StatusOK || json.Unmarshal(raw, &out) != nil {
		e.t.Fatalf("list requests: %d %s", code, raw)
	}
	return out
}

func (e *env) access(u *store.User, app string) string {
	e.t.Helper()
	eff, err := e.st.EffectiveAppsFrom(context.Background(), u, "")
	if err != nil {
		e.t.Fatal(err)
	}
	return eff[app]
}

// App requests: who can ask, one pending per person per app, a daily limit,
// and what approving and declining do (access rule, licence, seats).
func TestAppRequests(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	app := "app" + secret.Hash(secret.Token())[:8]
	addApp(t, e, app)
	if err := e.st.SetAppPolicy(ctx, e.org.ID, app, store.AppDisabled); err != nil {
		t.Fatal(err)
	}
	ann, bob, cat := e.user("ann", "member"), e.user("bob", "member"), e.user("cat", "member")
	other := e.user("other", "member")
	// A manager with only the licences permission, and one with only apps.
	licMgr, appMgr := e.user("licmgr", "member"), e.user("appmgr", "member")
	for _, m := range []struct {
		u    *store.User
		perm string
	}{{licMgr, store.PermLicences}, {appMgr, store.PermApps}} {
		g := e.group("G"+m.u.Name, m.perm)
		if err := e.st.AddGroupMember(ctx, g.ID, m.u.ID); err != nil {
			t.Fatal(err)
		}
	}

	// Creation rules.
	if _, err := e.st.CreateAppRequest(ctx, ann, app, "  ", ""); !errors.Is(err, store.ErrReasonInvalid) {
		t.Errorf("empty reason: %v", err)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, app, strings.Repeat("x", 501), ""); !errors.Is(err, store.ErrReasonInvalid) {
		t.Errorf("long reason: %v", err)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, "nope", "please", ""); !errors.Is(err, store.ErrNotRequestable) {
		t.Errorf("unknown app: %v", err)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, "admin", "please", ""); !errors.Is(err, store.ErrNotRequestable) {
		t.Errorf("keston admin: %v", err)
	}
	other2 := "own" + secret.Hash(secret.Token())[:8]
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, organisation_id)
		SELECT $1, 'Foreign', 'x', '{}', id FROM organisations WHERE id <> $2 LIMIT 1`, other2, e.org.ID); err == nil {
		if _, err := e.st.CreateAppRequest(ctx, ann, other2, "please", ""); !errors.Is(err, store.ErrNotRequestable) {
			t.Errorf("another organisation's app: %v", err)
		}
	}
	// Apps they can already use can't be requested.
	open := "open" + secret.Hash(secret.Token())[:8]
	addApp(t, e, open)
	if _, err := e.st.CreateAppRequest(ctx, ann, open, "please", ""); !errors.Is(err, store.ErrAlreadyHasAccess) {
		t.Errorf("already has access: %v", err)
	}
	list, _ := e.st.RequestableApps(ctx, ann, "")
	if !hasClient(list, app) || hasClient(list, open) {
		t.Errorf("requestable apps: %+v", list)
	}

	// Duplicates: one pending per person per app.
	first, err := e.st.CreateAppRequest(ctx, ann, app, "For the newsletter", "")
	if err != nil || first.Status != store.RequestPending {
		t.Fatalf("create: %+v %v", first, err)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, app, "again", ""); !errors.Is(err, store.ErrPending) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := e.st.CreateAppRequest(ctx, bob, app, "Me too", ""); err != nil {
		t.Errorf("someone else's: %v", err)
	}
	// Admins were told.
	notes, _ := e.st.Notifications(ctx, admin.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Title, "asked for") || notes[0].Link != "/app-requests" {
		t.Errorf("admin notification: %+v", notes)
	}
	if n, _ := e.st.Notifications(ctx, ann.ID); len(n) != 0 {
		t.Errorf("requester notified of own request: %+v", n)
	}

	// Rate limit: 5 in 24 hours.
	for i := 0; i < store.RequestsPerDay-1; i++ { // ann has made one
		id := "lim" + secret.Hash(secret.Token())[:8]
		addApp(t, e, id)
		_ = e.st.SetAppPolicy(ctx, e.org.ID, id, store.AppDisabled)
		if _, err := e.st.CreateAppRequest(ctx, ann, id, "r", ""); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	extra := "lim" + secret.Hash(secret.Token())[:8]
	addApp(t, e, extra)
	_ = e.st.SetAppPolicy(ctx, e.org.ID, extra, store.AppDisabled)
	if _, err := e.st.CreateAppRequest(ctx, ann, extra, "r", ""); !errors.Is(err, store.ErrRateLimited) {
		t.Errorf("rate limit: %v", err)
	}

	// Permissions: members can't see or decide; the managers can.
	if code, _ := e.do(other, http.MethodGet, "/app-requests", nil); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Errorf("member lists: %d", code)
	}
	if code, _ := e.do(other, http.MethodPost, "/app-requests/"+first.ID+"/approve", nil); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Errorf("member approves: %d", code)
	}
	if code, _ := e.do(other, http.MethodPut, "/app-request-settings", map[string]any{"enabled": false}); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Errorf("member settings: %d", code)
	}
	if code, _ := e.do(licMgr, http.MethodGet, "/app-requests", nil); code != http.StatusOK {
		t.Errorf("licence manager lists: %d", code)
	}
	// Approving would change app access: licences alone isn't enough.
	if code, _ := e.do(licMgr, http.MethodPost, "/app-requests/"+first.ID+"/approve", nil); code != http.StatusForbidden {
		t.Errorf("licence manager approves access change: %d", code)
	}
	pending := e.requests(admin, "?status=pending&app="+app)
	if len(pending) != 2 || pending[0].Plan == nil || !pending[0].Plan.AddToRule || pending[0].Plan.AssignLicence {
		t.Fatalf("pending with plan: %+v", pending)
	}
	var cnt struct{ Pending int }
	_, raw := e.do(appMgr, http.MethodGet, "/app-requests/count", nil)
	_ = json.Unmarshal(raw, &cnt)
	if cnt.Pending < 2 {
		t.Errorf("count: %s", raw)
	}

	// Approve: ann is added to the "Approved requests" rule, which wins over the default.
	if got := e.access(ann, app); got != store.AppDisabled {
		t.Fatalf("before: %q", got)
	}
	if code, raw := e.do(appMgr, http.MethodPost, "/app-requests/"+first.ID+"/approve", map[string]any{"message": "Welcome"}); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, raw)
	}
	if got := e.access(ann, app); got != store.AppEnabled {
		t.Errorf("after approving: %q", got)
	}
	if got := e.access(bob, app); got != store.AppDisabled {
		t.Errorf("bob unaffected: %q", got)
	}
	n, _ := e.st.Notifications(ctx, ann.ID)
	if len(n) == 0 || !strings.Contains(n[0].Title, "approved") {
		t.Errorf("requester notification: %+v", n)
	}
	// Approving again, or declining a decided one, fails; and a new request
	// isn't needed (she has access).
	if code, _ := e.do(admin, http.MethodPost, "/app-requests/"+first.ID+"/approve", nil); code != http.StatusConflict {
		t.Errorf("approve twice: %d", code)
	}
	if code, _ := e.do(admin, http.MethodPost, "/app-requests/"+first.ID+"/decline", nil); code != http.StatusConflict {
		t.Errorf("decline decided: %d", code)
	}
	// A second approval reuses the same rule.
	second, err := e.st.CreateAppRequest(ctx, cat, app, "Cat needs it", "")
	if err != nil {
		t.Fatal(err)
	}
	if code, raw := e.do(admin, http.MethodPost, "/app-requests/"+second.ID+"/approve", nil); code != http.StatusOK {
		t.Fatalf("approve 2: %d %s", code, raw)
	}
	rules, _ := e.st.AppRules(ctx, e.org.ID, app)
	if len(rules) != 1 || rules[0].Name != store.ApprovedRulesName || len(rules[0].Users) != 2 {
		t.Errorf("approved rule: %+v", rules)
	}

	// Decline, with a message.
	bobReq := e.requests(admin, "?status=pending&app="+app)
	if len(bobReq) != 1 {
		t.Fatalf("bob's pending: %+v", bobReq)
	}
	if code, _ := e.do(admin, http.MethodPost, "/app-requests/"+bobReq[0].ID+"/decline", map[string]any{"message": "Not this term"}); code != http.StatusOK {
		t.Fatalf("decline: %d", code)
	}
	if got := e.access(bob, app); got != store.AppDisabled {
		t.Errorf("declined: %q", got)
	}
	declined := e.requests(admin, "?status=declined")
	if len(declined) != 1 || declined[0].DecisionMessage != "Not this term" {
		t.Errorf("declined list: %+v", declined)
	}
	if n, _ := e.st.Notifications(ctx, bob.ID); len(n) == 0 || !strings.Contains(n[0].Body, "Not this term") {
		t.Errorf("decline notification: %+v", n)
	}
	// Declined: they may ask again.
	if _, err := e.st.CreateAppRequest(ctx, bob, app, "Please reconsider", ""); err != nil {
		t.Errorf("ask again after decline: %v", err)
	}

	// Audit trail.
	var actions []string
	rows, _ := e.st.DB.Query(ctx, `SELECT action FROM audit_log WHERE organisation_id = $1 AND action LIKE 'app_request.%'`, e.org.ID)
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	for _, want := range []string{store.ActionAppRequested, store.ActionAppRequestApproved, store.ActionAppRequestDeclined} {
		found := false
		for _, a := range actions {
			found = found || a == want
		}
		if !found {
			t.Errorf("audit missing %s: %v", want, actions)
		}
	}
}

func hasClient(list []store.Client, id string) bool {
	for _, c := range list {
		if c.ID == id {
			return true
		}
	}
	return false
}

// Approving a request for a Keston product assigns the licence within the
// organisation's seats; with none left it fails clearly and changes nothing.
func TestAppRequestLicences(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	ann, bob, cat := e.user("ann", "member"), e.user("bob", "member"), e.user("cat", "member")
	used := 0
	if ps, err := e.st.Products(ctx, e.org.ID); err == nil {
		for _, p := range ps {
			if p.ID == "work" {
				used = p.Assigned
			}
		}
	}
	// One seat left.
	one := used + 1
	if _, err := e.st.SetAllocations(ctx, e.org.ID, nil, map[string]*int{"work": &one}); err != nil {
		t.Fatal(err)
	}
	ra, err := e.st.CreateAppRequest(ctx, ann, "work", "Need it for marking", "")
	if err != nil {
		t.Fatal(err)
	}
	rb, err := e.st.CreateAppRequest(ctx, bob, "work", "And me", "")
	if err != nil {
		t.Fatal(err)
	}
	pend := e.requests(admin, "?status=pending&app=work")
	if len(pend) != 2 || pend[0].Plan == nil || !pend[0].Plan.AssignLicence || pend[0].Plan.AddToRule {
		t.Fatalf("plan: %+v", pend)
	}
	// Assigning needs the licences permission: an apps-only manager can't.
	g := e.group("Apps only", store.PermApps)
	mgr := e.user("mgr", "member")
	_ = e.st.AddGroupMember(ctx, g.ID, mgr.ID)
	if code, _ := e.do(mgr, http.MethodPost, "/app-requests/"+ra.ID+"/approve", nil); code != http.StatusForbidden {
		t.Errorf("apps-only assigns licence: %d", code)
	}
	if code, raw := e.do(admin, http.MethodPost, "/app-requests/"+ra.ID+"/approve", nil); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, raw)
	}
	if lic, _ := e.st.Licences(ctx, ann.ID); len(lic) != 1 || lic[0] != "work" {
		t.Errorf("licence assigned: %v", lic)
	}
	if got := e.access(ann, "work"); got != store.AppForced {
		t.Errorf("access: %q", got)
	}
	// No seats left: a clear error, and bob stays pending, unlicensed.
	code, raw := e.do(admin, http.MethodPost, "/app-requests/"+rb.ID+"/approve", nil)
	if code != http.StatusConflict || !strings.Contains(string(raw), "no_seats") || !strings.Contains(string(raw), "no Keston Work licences left") {
		t.Errorf("no seats: %d %s", code, raw)
	}
	if lic, _ := e.st.Licences(ctx, bob.ID); len(lic) != 0 {
		t.Errorf("licence given anyway: %v", lic)
	}
	if got, _ := e.st.AppRequestByID(ctx, e.org.ID, rb.ID); got.Status != store.RequestPending {
		t.Errorf("status after failure: %s", got.Status)
	}
	// Bulk: approving bob fails (skipped, with the reason), declining cat works.
	rc, err := e.st.CreateAppRequest(ctx, cat, "work", "Cat", "")
	if err != nil {
		t.Fatal(err)
	}
	code, raw = e.do(admin, http.MethodPost, "/app-requests/bulk", map[string]any{"ids": []string{rb.ID}, "action": "approve"})
	var bulk struct {
		Results []struct{ Result, Reason string }
	}
	_ = json.Unmarshal(raw, &bulk)
	if code != http.StatusOK || len(bulk.Results) != 1 || bulk.Results[0].Result != "skipped" || !strings.Contains(bulk.Results[0].Reason, "no ") {
		t.Errorf("bulk approve: %d %s", code, raw)
	}
	code, raw = e.do(admin, http.MethodPost, "/app-requests/bulk", map[string]any{"ids": []string{rb.ID, rc.ID}, "action": "decline", "message": "No seats"})
	_ = json.Unmarshal(raw, &bulk)
	if code != http.StatusOK || len(bulk.Results) != 2 || bulk.Results[0].Result != "done" || bulk.Results[1].Result != "done" {
		t.Errorf("bulk decline: %d %s", code, raw)
	}
	// More seats, then she can ask again and be approved.
	two := used + 3
	_, _ = e.st.SetAllocations(ctx, e.org.ID, nil, map[string]*int{"work": &two})
	rb2, err := e.st.CreateAppRequest(ctx, bob, "work", "Again", "")
	if err != nil {
		t.Fatal(err)
	}
	if code, raw := e.do(admin, http.MethodPost, "/app-requests/"+rb2.ID+"/approve", nil); code != http.StatusOK {
		t.Errorf("approve with seats: %d %s", code, raw)
	}
}

// "Let people request apps" and the apps that can't be requested.
func TestAppRequestSettings(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	ann := e.user("ann", "member")
	a1, a2 := "ra"+secret.Hash(secret.Token())[:8], "rb"+secret.Hash(secret.Token())[:8]
	for _, id := range []string{a1, a2} {
		addApp(t, e, id)
		_ = e.st.SetAppPolicy(ctx, e.org.ID, id, store.AppDisabled)
	}
	code, raw := e.do(admin, http.MethodGet, "/app-request-settings", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), `"enabled":true`) {
		t.Fatalf("default on: %d %s", code, raw)
	}
	if code, _ := e.do(admin, http.MethodPut, "/app-request-settings", map[string]any{"enabled": true, "excluded": []string{"nope"}}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown excluded app: %d", code)
	}
	if code, raw := e.do(admin, http.MethodPut, "/app-request-settings", map[string]any{"enabled": true, "excluded": []string{a2}}); code != http.StatusOK {
		t.Fatalf("exclude: %d %s", code, raw)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, a2, "please", ""); !errors.Is(err, store.ErrNotRequestable) {
		t.Errorf("excluded: %v", err)
	}
	if _, err := e.st.CreateAppRequest(ctx, ann, a1, "please", ""); err != nil {
		t.Errorf("not excluded: %v", err)
	}
	e.do(admin, http.MethodPut, "/app-request-settings", map[string]any{"enabled": false, "excluded": []string{}})
	if _, err := e.st.CreateAppRequest(ctx, ann, a2, "please", ""); !errors.Is(err, store.ErrRequestsOff) {
		t.Errorf("off: %v", err)
	}
	if list, _ := e.st.RequestableApps(ctx, ann, ""); len(list) != 0 {
		t.Errorf("requestable while off: %d", len(list))
	}
}
