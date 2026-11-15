//go:build e2e

// End-to-end tests for sign-in requirements in Keston Admin's API: the
// real handlers and permission checks against a real Postgres. Signing in
// (access tokens) is replaced by putting the caller in the context.
//
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55420/keston_id?sslmode=disable \
//	  go test -tags e2e ./internal/adminapi/
package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

const pw = "correct horse battery staple"

type env struct {
	t   *testing.T
	st  *store.Store
	a   *API
	org *store.Organisation
}

func setup(t *testing.T) *env {
	t.Helper()
	url := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KESTON_ID_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	box, _ := secret.NewBox([32]byte{1})
	st := store.New(pool, box)
	domain := "org-" + secret.Hash(secret.Token())[:10] + ".test"
	org, _, err := st.CreateOrganisation(ctx, "Org "+t.Name(), domain, store.NewUser{Email: "admin@" + domain,
		Name: "Admin", PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, a: New(st, nil, "http://id.test"), org: org}
}

func (e *env) user(name string, perms ...string) *store.User {
	e.t.Helper()
	ctx := context.Background()
	u, err := e.st.CreateUser(ctx, e.st.DB, store.NewUser{OrganisationID: e.org.ID, Email: name + "@" + e.org.Domain,
		Name: name, PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		e.t.Fatal(err)
	}
	if len(perms) > 0 {
		g, err := e.st.CreateGroup(ctx, e.org.ID, name+" perms")
		if err != nil {
			e.t.Fatal(err)
		}
		_ = e.st.SetGroupPermissions(ctx, g.ID, store.CleanPermissions(perms))
		_ = e.st.AddGroupMember(ctx, g.ID, u.ID)
	}
	return u
}

// as: a request from this user, through the same permission checks as
// Routes() (requireView, need), with the handlers under test.
func (e *env) as(u *store.User, method, path string, body any, out any) int {
	e.t.Helper()
	ctx := context.Background()
	u, _ = e.st.UserByID(ctx, u.ID)
	perms, _ := e.st.PermissionsOf(ctx, u)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := context.WithValue(r.Context(), userKey, u)
			next.ServeHTTP(w, r.WithContext(context.WithValue(c, permsKey, perms)))
		})
	})
	a := e.a
	r.Route("/organisations/{orgID}", func(r chi.Router) {
		r.Use(a.requireView)
		r.With(a.need(store.PermCreateUsers)).Post("/users", a.createUser)
		r.With(a.need(store.PermResetPassword)).Post("/users/{userID}/reset-password", a.resetPassword)
		r.With(a.need(store.PermPolicy)).Get("/mfa-policy", a.getMFAPolicy)
		r.With(a.need(store.PermPolicy)).Put("/mfa-policy", a.putMFAPolicy)
		r.With(a.need(store.PermPolicy)).Put("/mfa-policy/groups/{groupID}", a.putGroupMFAPolicy)
		r.With(a.need(store.PermViewUsers)).Get("/users/{userID}/sign-in", a.getSignIn)
		r.With(a.need(store.PermResetPassword)).Post("/users/{userID}/require-password-change", a.requirePasswordChange)
		r.With(a.need(store.PermAccessPass)).Post("/users/{userID}/access-passes", a.createAccessPass)
		r.With(a.need(store.PermAccessPass)).Delete("/users/{userID}/access-passes/{passID}", a.revokeAccessPass)
	})
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/organisations/"+e.org.ID+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if body != nil {
		req.ContentLength = int64(buf.Len())
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if out != nil {
		_ = json.Unmarshal(rec.Body.Bytes(), out)
	}
	return rec.Code
}

func (e *env) required(u *store.User) bool {
	st, err := e.st.SignInState(context.Background(), u)
	if err != nil {
		e.t.Fatal(err)
	}
	return st.PasswordChangeRequired
}

func TestPasswordChangeTickBox(t *testing.T) {
	e := setup(t)
	admin := e.user("helpdesk", store.PermCreateUsers, store.PermResetPassword)

	var created struct{ ID string }
	if n := e.as(admin, "POST", "/users", map[string]any{"name": "New", "username": "new1", "password": pw},
		&created); n != 201 {
		t.Fatalf("create: %d", n)
	}
	if !e.required(&store.User{ID: created.ID}) {
		t.Fatal("default should require a password change")
	}
	if n := e.as(admin, "POST", "/users", map[string]any{"name": "New", "username": "new2", "password": pw,
		"requirePasswordChange": false}, &created); n != 201 {
		t.Fatalf("create: %d", n)
	}
	u2 := &store.User{ID: created.ID}
	if e.required(u2) {
		t.Fatal("unticked, but required")
	}
	// Reset: on by default; unticked turns it off again.
	if n := e.as(admin, "POST", "/users/"+u2.ID+"/reset-password", map[string]any{"password": pw + "!"}, nil); n != 204 {
		t.Fatalf("reset: %d", n)
	}
	if !e.required(u2) {
		t.Fatal("reset should require a change")
	}
	e.as(admin, "POST", "/users/"+u2.ID+"/reset-password", map[string]any{"password": pw + "!",
		"requirePasswordChange": false}, nil)
	if e.required(u2) {
		t.Fatal("unticked reset still requires a change")
	}
	// The action on the user page.
	if n := e.as(admin, "POST", "/users/"+u2.ID+"/require-password-change", nil, nil); n != 204 || !e.required(u2) {
		t.Fatalf("require: %d", n)
	}
	var state struct {
		PasswordChangeRequired bool `json:"passwordChangeRequired"`
	}
	if n := e.as(admin, "GET", "/users/"+u2.ID+"/sign-in", nil, &state); n != 200 || !state.PasswordChangeRequired {
		t.Fatalf("sign-in state: %d %+v", n, state)
	}
	// Someone without the permission can't.
	viewer := e.user("viewer", store.PermViewUsers)
	if n := e.as(viewer, "POST", "/users/"+u2.ID+"/require-password-change", nil, nil); n != 403 {
		t.Fatalf("viewer: %d", n)
	}
}

func TestMFAPolicyEndpoints(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.user("sec", store.PermPolicy)
	g, _ := e.st.CreateGroup(ctx, e.org.ID, "Staff")
	var p store.MFAPolicy
	if n := e.as(admin, "PUT", "/mfa-policy", map[string]any{"required": true}, &p); n != 200 || !p.Required {
		t.Fatalf("default: %d %+v", n, p)
	}
	if n := e.as(admin, "PUT", "/mfa-policy/groups/"+g.ID, map[string]any{"required": false}, &p); n != 200 {
		t.Fatalf("group: %d", n)
	}
	found := false
	for _, x := range p.Groups {
		if x.ID == g.ID {
			found = x.Required != nil && !*x.Required
		}
	}
	if !found {
		t.Fatalf("group setting not saved: %+v", p.Groups)
	}
	if n := e.as(admin, "PUT", "/mfa-policy/groups/"+g.ID, map[string]any{"required": nil}, &p); n != 200 {
		t.Fatalf("group back to default: %d", n)
	}
	for _, x := range p.Groups {
		if x.ID == g.ID && x.Required != nil {
			t.Fatal("not back to the default")
		}
	}
	if n := e.as(admin, "PUT", "/mfa-policy/groups/not-a-group", map[string]any{"required": true}, nil); n != 404 {
		t.Fatalf("unknown group: %d", n)
	}
	noPerm := e.user("nope", store.PermViewUsers)
	if n := e.as(noPerm, "PUT", "/mfa-policy", map[string]any{"required": false}, nil); n != 403 {
		t.Fatalf("without permission: %d", n)
	}
}

func TestAccessPassEndpoints(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	issuer := e.user("issuer", store.PermAccessPass)
	target := e.user("target")
	// Someone with a permission the issuer doesn't have: can't be given one.
	above := e.user("above", store.PermAccessPass, store.PermApps)

	var created struct {
		Code string `json:"code"`
		Pass struct {
			ID      string `json:"id"`
			OneTime bool   `json:"oneTime"`
			Active  bool   `json:"active"`
		} `json:"pass"`
	}
	for _, hours := range []int{0, 9} {
		if n := e.as(issuer, "POST", "/users/"+target.ID+"/access-passes", map[string]any{"hours": hours}, nil); n != 422 {
			t.Fatalf("%d hours: %d", hours, n)
		}
	}
	if n := e.as(issuer, "POST", "/users/"+target.ID+"/access-passes", map[string]any{"hours": 2, "oneTime": true,
		"requirePasswordChange": true}, &created); n != 201 || len(created.Code) != 19 || !created.Pass.Active {
		t.Fatalf("issue: %d %+v", n, created)
	}
	if !e.required(target) {
		t.Fatal("password change not required")
	}
	// The code works (stored hashed), once.
	if ok, _ := e.st.UseAccessPass(ctx, target.ID, secret.Hash(secret.NormaliseAccessPass(created.Code))); !ok {
		t.Fatal("code doesn't work")
	}
	var raw string
	_ = e.st.DB.QueryRow(ctx, `SELECT code_hash FROM access_passes WHERE id = $1`, created.Pass.ID).Scan(&raw)
	if strings.Contains(raw, strings.ReplaceAll(created.Code, "-", "")) {
		t.Fatal("code stored in plain text")
	}

	var state struct {
		AccessPasses []struct {
			ID     string `json:"id"`
			Active bool   `json:"active"`
			Code   string `json:"code"`
		} `json:"accessPasses"`
	}
	e.as(issuer, "POST", "/users/"+target.ID+"/access-passes", map[string]any{"hours": 8}, &created)
	// Seeing them needs See users, which Issue access passes brings.
	if n := e.as(issuer, "GET", "/users/"+target.ID+"/sign-in", nil, &state); n != 200 {
		t.Fatalf("list: %d", n)
	}
	if len(state.AccessPasses) != 2 || !state.AccessPasses[0].Active || state.AccessPasses[1].Active ||
		state.AccessPasses[0].Code != "" {
		t.Fatalf("list: %+v", state.AccessPasses)
	}
	if n := e.as(issuer, "DELETE", "/users/"+target.ID+"/access-passes/"+created.Pass.ID, nil, nil); n != 204 {
		t.Fatalf("revoke: %d", n)
	}
	if n := e.as(issuer, "DELETE", "/users/"+target.ID+"/access-passes/nonsense", nil, nil); n != 404 {
		t.Fatalf("revoke unknown: %d", n)
	}
	e.as(issuer, "GET", "/users/"+target.ID+"/sign-in", nil, &state)
	if state.AccessPasses[0].Active {
		t.Fatal("revoked pass still active")
	}

	if n := e.as(issuer, "POST", "/users/"+above.ID+"/access-passes", map[string]any{"hours": 1}, nil); n != 403 {
		t.Fatalf("pass for someone above them: %d", n)
	}
	plain := e.user("plain", store.PermViewUsers)
	if n := e.as(plain, "POST", "/users/"+target.ID+"/access-passes", map[string]any{"hours": 1}, nil); n != 403 {
		t.Fatalf("without permission: %d", n)
	}
	_ = e.st.SetUserStatus(ctx, target.ID, "disabled")
	if n := e.as(issuer, "POST", "/users/"+target.ID+"/access-passes", map[string]any{"hours": 1}, nil); n != 409 {
		t.Fatalf("disabled user: %d", n)
	}
}
