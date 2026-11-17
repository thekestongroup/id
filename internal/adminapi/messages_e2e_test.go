//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

func (e *env) secondOrg() (*store.Organisation, *store.User) {
	e.t.Helper()
	domain := "o" + strings.ToLower(secret.Token()[:10]) + ".test"
	org, _, err := e.st.CreateOrganisation(context.Background(), "Other School", domain, store.NewUser{
		Email: "admin@" + domain, Name: "Olly Admin", PasswordHash: secret.HashPassword("x")})
	if err != nil {
		e.t.Fatal(err)
	}
	admin, err := e.st.UserByEmail(context.Background(), "admin@"+domain)
	if err != nil {
		e.t.Fatal(err)
	}
	return org, admin
}

func decodeInto[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return v
}

func (e *env) messages(as *store.User) messagesJSON {
	e.t.Helper()
	code, raw := e.call(as, http.MethodGet, "/messages", nil)
	if code != http.StatusOK {
		e.t.Fatalf("list messages: %d %s", code, raw)
	}
	return decodeInto[messagesJSON](e.t, raw)
}

func (e *env) unreadBell(u *store.User, title string) int {
	e.t.Helper()
	var n int
	if err := e.st.DB.QueryRow(context.Background(), `SELECT count(*) FROM notifications WHERE user_id = $1 AND title = $2`,
		u.ID, title).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// Only TKG Admins post; non-admins don't even read.
func TestMessagePermissions(t *testing.T) {
	e := setup(t)
	_, staff := e.platformAdmin()
	admin := e.admin()
	member := e.user("mia", "member")
	body := map[string]any{"title": "Hello", "body": "Body", "category": "notice", "allOrganisations": true}

	for _, u := range []*store.User{admin, member} {
		if code, _ := e.call(u, http.MethodPost, "/messages", body); code != http.StatusForbidden {
			t.Errorf("%s posts: %d", u.Role, code)
		}
		if code, _ := e.call(u, http.MethodGet, "/messages/all", nil); code != http.StatusForbidden {
			t.Errorf("%s lists all: %d", u.Role, code)
		}
	}
	if code, _ := e.call(member, http.MethodGet, "/messages", nil); code != http.StatusForbidden {
		t.Errorf("a member reads messages: %d", code)
	}
	if code, _ := e.call(member, http.MethodGet, "/health", nil); code != http.StatusForbidden {
		t.Errorf("a member reads health: %d", code)
	}
	code, raw := e.call(staff, http.MethodPost, "/messages", body)
	if code != http.StatusCreated {
		t.Fatalf("TKG Admin posts: %d %s", code, raw)
	}
	m := decodeInto[store.Message](t, raw)
	if code, _ := e.call(admin, http.MethodPut, "/messages/"+m.ID, body); code != http.StatusForbidden {
		t.Errorf("admin edits: %d", code)
	}
	if code, _ := e.call(admin, http.MethodDelete, "/messages/"+m.ID, nil); code != http.StatusForbidden {
		t.Errorf("admin deletes: %d", code)
	}
	body["title"] = "Hello again"
	if code, _ := e.call(staff, http.MethodPut, "/messages/"+m.ID, body); code != http.StatusOK {
		t.Errorf("TKG Admin edits: %d", code)
	}

	// Validation.
	for name, bad := range map[string]map[string]any{
		"no title":   {"title": " ", "body": "x", "category": "notice", "allOrganisations": true},
		"bad cat":    {"title": "x", "body": "x", "category": "spam", "allOrganisations": true},
		"no targets": {"title": "x", "body": "x", "category": "notice", "allOrganisations": false},
		"bad org":    {"title": "x", "body": "x", "category": "notice", "organisationIds": []string{"00000000-0000-0000-0000-000000000001"}},
		"bad date":   {"title": "x", "body": "x", "category": "notice", "allOrganisations": true, "actionBy": "tomorrow"},
	} {
		if code, _ := e.call(staff, http.MethodPost, "/messages", bad); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", name, code)
		}
	}

	// Audited, in the poster's organisation.
	var logged int
	if err := e.st.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE target_id = $1 AND action IN ($2, $3)`,
		m.ID, store.ActionMessagePosted, store.ActionMessageUpdated).Scan(&logged); err != nil || logged != 2 {
		t.Errorf("audit entries: %d %v", logged, err)
	}
	if code, _ := e.call(staff, http.MethodDelete, "/messages/"+m.ID, nil); code != http.StatusNoContent {
		t.Errorf("TKG Admin deletes: %d", code)
	}
}

// Targeting, the bell and per-admin read state.
func TestMessageTargetingAndReadState(t *testing.T) {
	e := setup(t)
	_, staff := e.platformAdmin()
	adminA := e.admin()
	adminA2 := e.user("second", "global_admin")
	_, adminB := e.secondOrg()
	orgA := e.org.ID

	post := func(body map[string]any) store.Message {
		t.Helper()
		code, raw := e.call(staff, http.MethodPost, "/messages", body)
		if code != http.StatusCreated {
			t.Fatalf("post: %d %s", code, raw)
		}
		return decodeInto[store.Message](t, raw)
	}
	tag := secret.Token()[:6]
	only := post(map[string]any{"title": "Only A " + tag, "body": "**Do it**", "category": "action_required",
		"actionBy": "2030-01-31", "organisationIds": []string{orgA}})
	all := post(map[string]any{"title": "Everyone " + tag, "body": "Hi", "category": "feature", "allOrganisations": true})

	// Targeting: B never sees the A-only message, nor gets a bell for it.
	has := func(list messagesJSON, id string) bool {
		for _, m := range list.Messages {
			if m.ID == id {
				return true
			}
		}
		return false
	}
	if a, b := e.messages(adminA), e.messages(adminB); !has(a, only.ID) || !has(a, all.ID) || has(b, only.ID) || !has(b, all.ID) {
		t.Fatalf("targeting: A sees only=%v all=%v; B sees only=%v all=%v", has(a, only.ID), has(a, all.ID), has(b, only.ID), has(b, all.ID))
	}
	if e.unreadBell(adminA, only.Title) != 1 || e.unreadBell(adminA2, only.Title) != 1 || e.unreadBell(adminB, only.Title) != 0 {
		t.Error("bell notifications for the targeted message")
	}
	if e.unreadBell(adminB, all.Title) != 1 {
		t.Error("bell for everyone's message")
	}
	if code, _ := e.call(adminB, http.MethodPost, "/messages/"+only.ID+"/read", nil); code != http.StatusNotFound {
		t.Errorf("reading a message that isn't for you: %d", code)
	}
	if code, _ := e.call(adminA, http.MethodPost, "/messages/not-a-uuid/read", nil); code != http.StatusNotFound {
		t.Errorf("bad id: %d", code)
	}

	// Read state is each admin's own.
	before := e.messages(adminA)
	if !has(before, only.ID) || before.Unread < 2 {
		t.Fatalf("unread: %+v", before.Unread)
	}
	foundAction := false
	for _, m := range before.ActionRequired {
		foundAction = foundAction || m.ID == only.ID
	}
	if !foundAction {
		t.Error("action required message isn't in actionRequired")
	}
	if code, _ := e.call(adminA, http.MethodPost, "/messages/"+only.ID+"/read", nil); code != http.StatusNoContent {
		t.Fatalf("read: %d", code)
	}
	after := e.messages(adminA)
	if after.Unread != before.Unread-1 {
		t.Errorf("unread %d → %d", before.Unread, after.Unread)
	}
	for _, m := range after.ActionRequired {
		if m.ID == only.ID {
			t.Error("a read message is still action required")
		}
	}
	other := e.messages(adminA2)
	for _, m := range other.Messages {
		if m.ID == only.ID && m.Read {
			t.Error("another admin's read state changed")
		}
	}

	// Archive hides it from the badge and keeps it listed; unread brings it back.
	if code, _ := e.call(adminA, http.MethodPost, "/messages/"+all.ID+"/archive", nil); code != http.StatusNoContent {
		t.Fatalf("archive: %d", code)
	}
	arch := e.messages(adminA)
	if arch.Unread != after.Unread-1 {
		t.Errorf("archived still counts: %d", arch.Unread)
	}
	archived := false
	for _, m := range arch.Messages {
		archived = archived || (m.ID == all.ID && m.Archived && m.Read)
	}
	if !archived {
		t.Error("not archived")
	}
	e.call(adminA, http.MethodPost, "/messages/"+all.ID+"/unarchive", nil)
	e.call(adminA, http.MethodPost, "/messages/"+only.ID+"/unread", nil)
	if back := e.messages(adminA); back.Unread != after.Unread {
		t.Errorf("after unarchive and unread: %d (was %d)", back.Unread, after.Unread)
	}
}

// Health: only TKG Admins write; statuses follow incidents and maintenance;
// banner data and the public endpoint.
func TestServiceHealth(t *testing.T) {
	e := setup(t)
	_, staff := e.platformAdmin()
	admin := e.admin()
	ctx := context.Background()
	// Start clean: the table is shared across runs.
	_, _ = e.st.DB.Exec(ctx, `DELETE FROM service_incidents`)
	_, _ = e.st.DB.Exec(ctx, `DELETE FROM maintenance_windows`)

	status := func(h healthJSON, id string) string {
		for _, s := range h.Services {
			if s.ID == id {
				return s.Status
			}
		}
		return ""
	}
	get := func() healthJSON {
		code, raw := e.call(admin, http.MethodGet, "/health", nil)
		if code != http.StatusOK {
			t.Fatalf("health: %d %s", code, raw)
		}
		return decodeInto[healthJSON](t, raw)
	}
	if h := get(); status(h, "work") != "operational" || h.CanManage {
		t.Fatalf("clean state: %+v", h)
	}
	inc := map[string]any{"title": "Sign-in is slow", "impact": "degraded", "status": "investigating",
		"services": []string{"keston-id", "work"}, "message": "Looking into it."}
	if code, _ := e.call(admin, http.MethodPost, "/health/incidents", inc); code != http.StatusForbidden {
		t.Errorf("admin opens an incident: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPost, "/health/incidents", map[string]any{"title": "x", "impact": "degraded", "services": []string{"nope"}, "message": "m"}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown service: %d", code)
	}
	code, raw := e.call(staff, http.MethodPost, "/health/incidents", inc)
	if code != http.StatusCreated {
		t.Fatalf("open: %d %s", code, raw)
	}
	created := decodeInto[store.Incident](t, raw)
	if h := get(); status(h, "work") != "degraded" || status(h, "keston-admin") != "operational" || len(h.Incidents) != 1 {
		t.Fatalf("degraded: %+v", h.Services)
	}
	if code, _ := e.call(admin, http.MethodPost, "/health/incidents/"+created.ID+"/updates", map[string]any{"status": "identified", "message": "m"}); code != http.StatusForbidden {
		t.Errorf("admin updates an incident: %d", code)
	}
	code, raw = e.call(staff, http.MethodPost, "/health/incidents/"+created.ID+"/updates",
		map[string]any{"status": "identified", "impact": "outage", "message": "Found it."})
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, raw)
	}
	if h := get(); status(h, "keston-id") != "outage" || len(h.Incidents[0].Updates) != 2 || h.Incidents[0].Updates[0].Message != "Found it." {
		t.Fatalf("outage: %+v", h)
	}
	// Public, unauthenticated, no author names.
	rec := httptest.NewRecorder()
	e.api.PublicRoutes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), staff.Name) {
		t.Errorf("public status: %d %s", rec.Code, rec.Body.String())
	}
	if code, _ := e.call(staff, http.MethodPost, "/health/incidents/"+created.ID+"/updates", map[string]any{"status": "resolved", "message": "Fixed."}); code != http.StatusOK {
		t.Fatal("resolve")
	}
	if h := get(); status(h, "keston-id") != "operational" || h.Incidents[0].ResolvedAt == nil {
		t.Fatalf("resolved: %+v", h)
	}

	// Maintenance: shows as maintenance while it runs.
	now := time.Now()
	mw := map[string]any{"title": "Database upgrade", "services": []string{"learn"},
		"startsAt": now.Add(-time.Hour), "endsAt": now.Add(time.Hour)}
	if code, _ := e.call(admin, http.MethodPost, "/health/maintenance", mw); code != http.StatusForbidden {
		t.Errorf("admin schedules maintenance: %d", code)
	}
	bad := map[string]any{"title": "x", "services": []string{"learn"}, "startsAt": now.Add(time.Hour), "endsAt": now}
	if code, _ := e.call(staff, http.MethodPost, "/health/maintenance", bad); code != http.StatusUnprocessableEntity {
		t.Errorf("ends before it starts: %d", code)
	}
	code, raw = e.call(staff, http.MethodPost, "/health/maintenance", mw)
	if code != http.StatusCreated {
		t.Fatalf("schedule: %d %s", code, raw)
	}
	win := decodeInto[store.Maintenance](t, raw)
	if h := get(); status(h, "learn") != "maintenance" || len(h.Maintenance) != 1 {
		t.Fatalf("maintenance: %+v", h)
	}
	if code, _ := e.call(staff, http.MethodDelete, "/health/maintenance/"+win.ID, nil); code != http.StatusNoContent {
		t.Fatal("cancel")
	}
	if h := get(); status(h, "learn") != "operational" {
		t.Fatalf("cancelled: %+v", h)
	}
	var logged int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target_id IN ($1, $2)`, created.ID, win.ID).Scan(&logged)
	if logged != 5 {
		t.Errorf("audit entries: %d", logged)
	}
}
