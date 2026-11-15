//go:build e2e

// End-to-end tests for deleting, restoring and bulk-changing users, against
// a real Postgres (KESTON_TEST_DATABASE_URL, default the throwaway one on
// port 55440) through the real handlers:
//
//	go test -tags e2e ./internal/adminapi/
package adminapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
	"github.com/thekestongroup/id/kit/auth"
)

const testIssuer = "http://id.test"

type env struct {
	t   *testing.T
	st  *store.Store
	api *API
	h   http.Handler
	key *rsa.PrivateKey
	org *store.Organisation
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("KESTON_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://keston:keston@localhost:55440/keston_id?sslmode=disable"
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris)
		VALUES ('admin', 'Keston Admin', 'The Keston Group', '{}') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}
	a := New(st, auth.NewVerifier(testIssuer, auth.AudienceKestonID, auth.StaticKeys{pub}), testIssuer)
	domain := "t" + strings.ToLower(secret.Token()[:10]) + ".test"
	org, _, err := st.CreateOrganisation(ctx, "Test School", domain, store.NewUser{
		Email: "admin@" + domain, Name: "Ada Admin", PasswordHash: secret.HashPassword("x")})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, api: a, h: a.Routes(), key: key, org: org}
}

func (e *env) user(username, role string) *store.User {
	e.t.Helper()
	u, err := e.st.CreateUser(context.Background(), e.st.DB, store.NewUser{OrganisationID: e.org.ID,
		Email: username + "@" + e.org.Domain, Name: username, Role: role, PasswordHash: secret.HashPassword("x")})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) admin() *store.User {
	u, err := e.st.UserByEmail(context.Background(), "admin@"+e.org.Domain)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) group(name string, perms ...string) *store.Group {
	e.t.Helper()
	ctx := context.Background()
	g, err := e.st.CreateGroup(ctx, e.org.ID, name)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(perms) > 0 {
		if err := e.st.SetGroupPermissions(ctx, g.ID, store.CleanPermissions(perms)); err != nil {
			e.t.Fatal(err)
		}
	}
	return g
}

// token: an access token for Keston Admin, as Keston ID would issue it.
func (e *env) token(u *store.User) string {
	e.t.Helper()
	id, _, err := e.st.CreateAccessToken(context.Background(), e.st.DB, "admin", &u.ID,
		[]string{auth.AudienceKestonID}, []string{"openid"}, nil, nil, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: e.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": testIssuer, "sub": u.ID,
		"aud": []string{auth.AudienceKestonID}, "exp": time.Now().Add(time.Hour).Unix(), "jti": id,
		"client_id": "admin"}).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *env) do(as *store.User, method, path string, body any) (int, []byte) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/organisations/"+e.org.ID+path, &buf)
	req.Header.Set("Authorization", "Bearer "+e.token(as))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// bulk: a bulk request, which must succeed; the results by user ID.
func (e *env) bulk(as *store.User, path string, body map[string]any) map[string]bulkResult {
	e.t.Helper()
	code, raw := e.do(as, http.MethodPost, path, body)
	if code != http.StatusOK {
		e.t.Fatalf("%s: %d %s", path, code, raw)
	}
	var out struct{ Results []bulkResult }
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatal(err)
	}
	m := map[string]bulkResult{}
	for _, r := range out.Results {
		m[r.ID] = r
	}
	return m
}

func ids(us ...*store.User) []string {
	out := []string{}
	for _, u := range us {
		out = append(out, u.ID)
	}
	return out
}

func expect(t *testing.T, res map[string]bulkResult, u *store.User, result, reason string) {
	t.Helper()
	r := res[u.ID]
	if r.Result != result || !strings.Contains(r.Reason, reason) {
		t.Errorf("%s: got %s (%q), want %s (%q)", u.Name, r.Result, r.Reason, result, reason)
	}
}

func (e *env) status(u *store.User) string {
	var s string
	if err := e.st.DB.QueryRow(context.Background(), `SELECT status FROM users WHERE id = $1`, u.ID).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func TestDeleteAndRestore(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	helper := e.user("helper", "member")
	alice := e.user("alice", "member")
	bob := e.user("bob", "member")
	boss := e.user("boss", "member")
	helpers := e.group("Helpers", store.PermUserStatus, store.PermDeleteUsers, store.PermResetPassword)
	bosses := e.group("Bosses", store.PermPolicy)
	pupils := e.group("Pupils")
	for _, m := range [][2]string{{helpers.ID, helper.ID}, {bosses.ID, boss.ID}, {pupils.ID, alice.ID}} {
		if err := e.st.AddGroupMember(ctx, m[0], m[1]); err != nil {
			t.Fatal(err)
		}
	}
	// A Keston support account in the organisation.
	var supportID string
	if err := e.st.DB.QueryRow(ctx, `INSERT INTO users (organisation_id, email, name, role, password_hash, support_for,
		expires_at) VALUES ($1, $2, 'Support', 'global_admin', '', $3, now() + interval '1 day') RETURNING id`,
		e.org.ID, "support@"+e.org.Domain, admin.ID).Scan(&supportID); err != nil {
		t.Fatal(err)
	}
	support := &store.User{ID: supportID, Name: "Support"}
	if _, _, err := e.st.CreateSession(ctx, alice.ID, "verified", []string{"pwd"}, "", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	aliceToken := e.token(alice)

	// Without "Delete users": refused outright.
	if code, _ := e.do(bob, http.MethodPost, "/users/bulk/delete", map[string]any{"userIds": ids(alice)}); code != http.StatusForbidden {
		t.Errorf("bob deleting: %d, want 403", code)
	}

	res := e.bulk(helper, "/users/bulk/delete", map[string]any{
		"userIds": append(ids(alice, admin, helper, boss, support), "00000000-0000-0000-0000-000000000000")})
	expect(t, res, alice, "done", "")
	expect(t, res, admin, "skipped", "permissions you don't")
	expect(t, res, boss, "skipped", "permissions you don't")
	expect(t, res, helper, "skipped", "yourself")
	expect(t, res, support, "skipped", "support")
	if r := res["00000000-0000-0000-0000-000000000000"]; r.Result != "skipped" || r.Reason != "Not found." {
		t.Errorf("unknown user: %+v", r)
	}

	// Alice is hidden, signed out and can't sign in.
	if s := e.status(alice); s != "deleted" {
		t.Errorf("alice status %s", s)
	}
	if got, _ := e.st.UserByID(ctx, alice.ID); got.Usable() {
		t.Error("deleted user still usable")
	}
	if sessions, _ := e.st.SessionsForUser(ctx, alice.ID); len(sessions) != 0 {
		t.Errorf("alice still has %d sessions", len(sessions))
	}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("deleted user's token: %d, want 401", rec.Code)
	}
	_, raw := e.do(admin, http.MethodGet, "/users", nil)
	if strings.Contains(string(raw), alice.ID) {
		t.Error("deleted user in the users list")
	}
	if code, _ := e.do(admin, http.MethodGet, "/users/"+alice.ID, nil); code != http.StatusNotFound {
		t.Errorf("deleted user's page: %d, want 404", code)
	}
	if g, _ := e.st.Group(ctx, e.org.ID, pupils.ID); g.MemberCount != 0 {
		t.Errorf("Pupils still counts %d members", g.MemberCount)
	}
	// Adding someone with her username is refused, pointing to Deleted users.
	code, raw := e.do(admin, http.MethodPost, "/users", map[string]any{"name": "Alice 2", "username": "alice",
		"password": "Correct-Horse-Battery-9"})
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(raw), "Deleted users") {
		t.Errorf("re-adding alice: %d %s", code, raw)
	}

	// She's in Deleted users for 30 days.
	code, raw = e.do(helper, http.MethodGet, "/deleted-users", nil)
	var deleted []struct {
		ID            string    `json:"id"`
		PurgeAfter    time.Time `json:"purgeAfter"`
		DeletedByName *string   `json:"deletedByName"`
		CanChange     bool      `json:"canChange"`
	}
	if err := json.Unmarshal(raw, &deleted); code != http.StatusOK || err != nil || len(deleted) != 1 {
		t.Fatalf("deleted users: %d %s", code, raw)
	}
	d := deleted[0]
	if d.ID != alice.ID || d.DeletedByName == nil || *d.DeletedByName != "helper" || !d.CanChange ||
		d.PurgeAfter.Sub(time.Now()) < 29*24*time.Hour {
		t.Errorf("deleted user: %+v", d)
	}

	// Restored, with her group and status back.
	res = e.bulk(helper, "/deleted-users/restore", map[string]any{"userIds": ids(alice, bob)})
	expect(t, res, alice, "done", "")
	expect(t, res, bob, "skipped", "Not found")
	if s := e.status(alice); s != "active" {
		t.Errorf("restored status %s", s)
	}
	if g, _ := e.st.Group(ctx, e.org.ID, pupils.ID); g.MemberCount != 1 {
		t.Errorf("Pupils has %d members after restoring, want 1", g.MemberCount)
	}

	// A disabled user comes back disabled.
	if err := e.st.SetUserStatus(ctx, bob.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if code, raw := e.do(helper, http.MethodDelete, "/users/"+bob.ID, nil); code != http.StatusNoContent {
		t.Fatalf("deleting bob: %d %s", code, raw)
	}
	e.bulk(helper, "/deleted-users/restore", map[string]any{"userIds": ids(bob)})
	if s := e.status(bob); s != "disabled" {
		t.Errorf("bob restored as %s, want disabled", s)
	}

	// After 30 days, housekeeping removes them for good.
	if code, _ := e.do(helper, http.MethodDelete, "/users/"+bob.ID, nil); code != http.StatusNoContent {
		t.Fatal("deleting bob again")
	}
	if _, err := e.st.DB.Exec(ctx, `UPDATE deleted_users SET purge_after = now() - interval '1 minute'
		WHERE user_id = $1`, bob.ID); err != nil {
		t.Fatal(err)
	}
	e.api.Housekeeping(ctx)
	if _, err := e.st.UserByID(ctx, bob.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob still there after purging: %v", err)
	}
	if _, err := e.st.UserByID(ctx, alice.ID); err != nil {
		t.Errorf("alice purged too: %v", err)
	}
}

func TestLastGlobalAdmin(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	second := e.user("second", "global_admin")

	// Deleting yourself is refused.
	if code, raw := e.do(admin, http.MethodDelete, "/users/"+admin.ID, nil); code != http.StatusConflict ||
		!strings.Contains(string(raw), "yourself") {
		t.Errorf("deleting yourself: %d %s", code, raw)
	}
	res := e.bulk(admin, "/users/bulk/delete", map[string]any{"userIds": ids(second)})
	expect(t, res, second, "done", "")
	// Now admin is the only global admin left (support accounts don't count).
	if err := e.st.DeleteUser(ctx, e.org.ID, admin.ID, second.ID); !errors.Is(err, store.ErrLastGlobalAdmin) {
		t.Errorf("deleting the last global admin: %v", err)
	}
}

func TestBulkResetStatusAndGroups(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	helper := e.user("helper", "member")
	alice := e.user("alice", "member")
	bob := e.user("bob", "member")
	helpers := e.group("Helpers", store.PermUserStatus, store.PermResetPassword, store.PermGroups)
	staff := e.group("Staff")
	givers := e.group("Givers", store.PermPolicy)
	if err := e.st.AddGroupMember(ctx, helpers.ID, helper.ID); err != nil {
		t.Fatal(err)
	}
	// A strict policy, which generated passwords must meet.
	if err := e.st.SetPasswordPolicy(ctx, e.org.ID, policy.Policy{MinLength: 20, MinUppercase: 3, MinDigits: 3,
		MinSpecial: 2}); err != nil {
		t.Fatal(err)
	}

	// Reset passwords: each their own, meeting the policy, working at once.
	res := e.bulk(helper, "/users/bulk/reset-password", map[string]any{"userIds": ids(alice, bob, admin)})
	expect(t, res, alice, "done", "")
	expect(t, res, bob, "done", "")
	expect(t, res, admin, "skipped", "permissions you don't")
	if res[alice.ID].Password == "" || res[alice.ID].Password == res[bob.ID].Password || res[admin.ID].Password != "" {
		t.Errorf("passwords: %+v", res)
	}
	org, _ := e.st.OrganisationByID(ctx, e.org.ID)
	for _, u := range []*store.User{alice, bob} {
		pw := res[u.ID].Password
		if failed := org.PasswordPolicy.Check(pw, u.Name); len(failed) > 0 {
			t.Errorf("%s's password %q fails %v", u.Name, pw, failed)
		}
		got, _ := e.st.UserByID(ctx, u.ID)
		if ok, _ := secret.CheckPassword(got.PasswordHash, pw); !ok {
			t.Errorf("%s's new password doesn't work", u.Name)
		}
	}

	// Disable and enable.
	res = e.bulk(helper, "/users/bulk/disable", map[string]any{"userIds": ids(alice, helper)})
	expect(t, res, alice, "done", "")
	expect(t, res, helper, "skipped", "yourself")
	res = e.bulk(helper, "/users/bulk/disable", map[string]any{"userIds": ids(alice)})
	expect(t, res, alice, "skipped", "Already disabled")
	res = e.bulk(helper, "/users/bulk/enable", map[string]any{"userIds": ids(alice, bob)})
	expect(t, res, alice, "done", "")
	expect(t, res, bob, "skipped", "Already enabled")
	if s := e.status(alice); s != "active" {
		t.Errorf("alice %s after enabling", s)
	}

	// Groups.
	res = e.bulk(helper, "/users/bulk/add-to-group", map[string]any{"groupId": staff.ID, "userIds": ids(alice, bob, admin)})
	expect(t, res, alice, "done", "")
	expect(t, res, admin, "skipped", "permissions you don't")
	res = e.bulk(helper, "/users/bulk/add-to-group", map[string]any{"groupId": staff.ID, "userIds": ids(alice)})
	expect(t, res, alice, "skipped", "Already in Staff")
	if g, _ := e.st.Group(ctx, e.org.ID, staff.ID); g.MemberCount != 2 {
		t.Errorf("Staff has %d members, want 2", g.MemberCount)
	}
	res = e.bulk(helper, "/users/bulk/remove-from-group", map[string]any{"groupId": staff.ID, "userIds": ids(alice, helper)})
	expect(t, res, alice, "done", "")
	expect(t, res, helper, "skipped", "Not in Staff")
	// A group that gives permissions the helper doesn't have: refused outright.
	if code, _ := e.do(helper, http.MethodPost, "/users/bulk/add-to-group",
		map[string]any{"groupId": givers.ID, "userIds": ids(alice)}); code != http.StatusForbidden {
		t.Errorf("adding to Givers: %d, want 403", code)
	}
	if code, _ := e.do(helper, http.MethodPost, "/users/bulk/add-to-group",
		map[string]any{"groupId": "00000000-0000-0000-0000-000000000000", "userIds": ids(alice)}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown group: %d, want 422", code)
	}
	if code, _ := e.do(helper, http.MethodPost, "/users/bulk/disable", map[string]any{"userIds": []string{}}); code != http.StatusBadRequest {
		t.Errorf("no users: %d, want 400", code)
	}
}
