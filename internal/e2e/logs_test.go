//go:build e2e

// End-to-end tests for the audit log and sign-in log, against a real
// Postgres (KESTON_TEST_DB, default the throwaway one on port 55410) and the
// real handlers:
//
//	go test -tags e2e ./internal/e2e/
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/thekestongroup/id/internal/adminapi"
	"github.com/thekestongroup/id/internal/api"
	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/principal"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
	"github.com/thekestongroup/id/kit/auth"
)

const issuer = "https://id.test"

type env struct {
	t     *testing.T
	st    *store.Store
	admin *adminapi.API
	srv   *httptest.Server
	key   *rsa.PrivateKey
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("KESTON_TEST_DB")
	if url == "" {
		url = "postgres://keston:keston@localhost:55410/keston_id?sslmode=disable"
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	box, err := secret.NewBox([32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(pool, box)
	for _, c := range []store.Client{
		{ID: "admin", Name: "Keston Admin", Publisher: "The Keston Group", Verification: "owned", Builtin: true},
		{ID: "work", Name: "Keston Work", Publisher: "The Keston Group", Verification: "owned", Builtin: true,
			RedirectURIs: []string{"https://work.test/cb"}, RequiredScopes: []string{"openid", "profile"}},
	} {
		for _, l := range []*[]string{&c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.RequiredScopes, &c.OptionalScopes} {
			if *l == nil {
				*l = []string{}
			}
		}
		if err := st.UpsertClient(ctx, &c, nil); err != nil {
			t.Fatal(err)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}
	verifier := auth.NewVerifier(issuer, auth.AudienceKestonID, auth.StaticKeys{pub})
	admin := adminapi.New(st, issuer)
	cfg := &config.Config{Issuer: issuer, SessionTTL: time.Hour, AuthRequestTTL: time.Hour}
	r := chi.NewRouter()
	id := api.New(st, cfg, func(context.Context, string) error { return nil })
	r.Mount("/api", id.Routes())
	r.Get("/support-sign-in", id.SupportSignIn)
	r.Route("/v1", func(r chi.Router) {
		r.Use(principal.Middleware(st, verifier, id.CookieSession))
		r.Mount("/", admin.Routes())
	})
	srv := httptest.NewTLSServer(r)
	t.Cleanup(srv.Close)
	return &env{t: t, st: st, admin: admin, srv: srv, key: key}
}

// token: a Keston Admin access token for u.
func (e *env) token(u *store.User) string {
	e.t.Helper()
	id, exp, err := e.st.CreateAccessToken(context.Background(), e.st.DB, "admin", &u.ID,
		[]string{auth.AudienceKestonID}, []string{"openid"}, nil, nil, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: e.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	raw, err := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "sub": u.ID,
		"aud": []string{"admin", auth.AudienceKestonID}, "exp": exp.Unix(), "client_id": "admin", "jti": id,
		"org": u.OrganisationID}).Serialize()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// call: an admin API request as tok, from ip. Returns the status and body.
func (e *env) call(tok, method, path string, body any, ip string) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/v1"+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

func (e *env) must(tok, method, path string, body any) []byte {
	e.t.Helper()
	status, out := e.call(tok, method, path, body, "203.0.113.7")
	if status >= 300 {
		e.t.Fatalf("%s %s: %d %s", method, path, status, out)
	}
	return out
}

type auditPage struct {
	Entries []store.AuditRecord `json:"entries"`
	Next    *string             `json:"next"`
}

type signInPage struct {
	Entries []store.SignInRecord `json:"entries"`
	Next    *string              `json:"next"`
}

// browser: a Keston ID web UI client (cookies kept).
type browser struct {
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := *e.srv.Client()
	c.Jar = jar
	return &browser{e, &c}
}

func (b *browser) post(path string, body any) (int, string) {
	b.e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, b.e.srv.URL+"/api"+path, bytes.NewReader(raw))
	req.Header.Set("X-Keston-ID", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "e2e-browser/1.0")
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	res, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

func (b *browser) get(path string) (int, string) {
	b.e.t.Helper()
	if !strings.HasPrefix(path, "/support-sign-in") {
		path = "/api" + path
	}
	req, _ := http.NewRequest(http.MethodGet, b.e.srv.URL+path, nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	res, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(out)
}

func TestLogs(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	domain := "greenfield" + suffix + ".test"
	const pw = "Correct-Horse-Battery-9"

	org, admin, err := e.st.CreateOrganisation(ctx, "Greenfield", domain, store.NewUser{
		Email: "head@" + domain, Name: "Head Teacher", PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.SetMFAMode(ctx, org.ID, store.MFAOff) // Not testing MFA here.
	other, otherAdmin, err := e.st.CreateOrganisation(ctx, "Elsewhere", "elsewhere"+suffix+".test", store.NewUser{
		Email: "boss@elsewhere" + suffix + ".test", Name: "Boss", PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.SetMFAMode(ctx, other.ID, store.MFAOff)
	adminTok := e.token(admin)
	base := "/organisations/" + org.ID

	// ── Admin actions are recorded ─────────────────────────────────────────

	var jo struct{ ID string }
	json.Unmarshal(e.must(adminTok, "POST", base+"/users", map[string]any{
		"name": "Jo Smith", "username": "jo", "password": pw}), &jo)
	e.must(adminTok, "PATCH", base+"/users/"+jo.ID, map[string]any{"name": "Jo Bloggs"})
	e.must(adminTok, "POST", base+"/users/"+jo.ID+"/status", map[string]any{"status": "disabled"})
	e.must(adminTok, "POST", base+"/users/"+jo.ID+"/reset-password", map[string]any{"password": pw + "x"})

	var g store.Group
	json.Unmarshal(e.must(adminTok, "POST", base+"/groups", map[string]any{"name": "Office"}), &g)
	e.must(adminTok, "PATCH", base+"/groups/"+g.ID, map[string]any{"name": "Office staff"})
	e.must(adminTok, "PUT", base+"/groups/"+g.ID+"/permissions", map[string]any{"permissions": []string{"reports.view"}})
	e.must(adminTok, "PUT", base+"/apps/work", map[string]any{"mode": "disabled"})
	e.must(adminTok, "PUT", base+"/settings", map[string]any{"profileEditing": map[string]bool{"name": true}})
	e.must(adminTok, "PUT", base+"/password-policy", map[string]any{"minLength": 14})

	var viewer, plain struct{ ID string }
	json.Unmarshal(e.must(adminTok, "POST", base+"/users", map[string]any{
		"name": "Vic Viewer", "username": "vic", "password": pw, "requirePasswordChange": false, "licences": []string{"work"}}), &viewer)
	json.Unmarshal(e.must(adminTok, "POST", base+"/users", map[string]any{
		"name": "Pat Plain", "username": "pat", "password": pw, "requirePasswordChange": false, "licences": []string{"work"}}), &plain)
	e.must(adminTok, "PUT", base+"/groups/"+g.ID+"/members/"+viewer.ID, nil)
	// Pat can see users, but not logs.
	g2, _ := e.st.CreateGroup(ctx, org.ID, "Helpers")
	_ = e.st.SetGroupPermissions(ctx, g2.ID, []string{"users.view"})
	_ = e.st.AddGroupMember(ctx, g2.ID, plain.ID)

	var log auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log", nil), &log)
	byAction := map[string]store.AuditRecord{}
	for _, r := range log.Entries {
		if _, seen := byAction[r.Action]; !seen {
			byAction[r.Action] = r
		}
	}
	for action, want := range map[string]string{
		store.ActionUserUpdated:       "Name: Jo Smith → Jo Bloggs",
		store.ActionUserDisabled:      "Status: Active → Disabled",
		store.ActionUserPasswordReset: "",
		store.ActionGroupRenamed:      "Name: Office → Office staff",
		store.ActionGroupPermissions:  "Permissions: none → See logs",
		store.ActionAppAccess:         "Everyone: Default → Disabled",
		store.ActionSettings:          "Change their name: Off → On",
		store.ActionPasswordPolicy:    "Minimum length: 8 → 14",
		store.ActionGroupMemberAdded:  "Group: Office staff",
	} {
		got, ok := byAction[action]
		if !ok {
			t.Errorf("%s: not logged", action)
			continue
		}
		if !strings.HasPrefix(got.Summary, want) {
			t.Errorf("%s: summary %q, want %q", action, got.Summary, want)
		}
		if got.ActorName != "Head Teacher" || got.IP != "203.0.113.7" || got.ActorID == nil || *got.ActorID != admin.ID {
			t.Errorf("%s: actor %q ip %q", action, got.ActorName, got.IP)
		}
	}
	if c := byAction[store.ActionUserCreated]; c.TargetType != "user" || c.Summary != "Role: Member" {
		t.Errorf("user.created: %+v", c)
	}

	// Filters: user, action, paging.
	var jos auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?user="+jo.ID, nil), &jos)
	if len(jos.Entries) != 4 {
		t.Errorf("Jo's entries: %d, want 4 (created, updated, disabled, reset)", len(jos.Entries))
	}
	var only auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?action=group.created,group.renamed", nil), &only)
	if len(only.Entries) != 2 {
		t.Errorf("group.created,group.renamed: %d entries", len(only.Entries))
	}
	var p1, p2 auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?limit=3", nil), &p1)
	if len(p1.Entries) != 3 || p1.Next == nil {
		t.Fatalf("page 1: %d entries, next %v", len(p1.Entries), p1.Next)
	}
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?limit=3&before="+*p1.Next, nil), &p2)
	if len(p2.Entries) != 3 || p2.Entries[0].ID >= p1.Entries[2].ID {
		t.Errorf("page 2 doesn't follow page 1")
	}
	var future auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?from=2099-01-01", nil), &future)
	if len(future.Entries) != 0 {
		t.Errorf("from=2099: %d entries", len(future.Entries))
	}
	var today auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?to="+time.Now().UTC().Format(time.DateOnly), nil), &today)
	if len(today.Entries) == 0 {
		t.Errorf("to=today: nothing (to should include the whole day)")
	}
	if s, _ := e.call(adminTok, "GET", base+"/audit-log?from=yesterday", nil, ""); s != http.StatusUnprocessableEntity {
		t.Errorf("bad date: %d", s)
	}

	// ── Who can see them ───────────────────────────────────────────────────

	vic, _ := e.st.UserByID(ctx, viewer.ID)
	pat, _ := e.st.UserByID(ctx, plain.ID)
	if s, _ := e.call(e.token(vic), "GET", base+"/sign-ins", nil, ""); s != http.StatusOK {
		t.Errorf("See logs: %d", s)
	}
	if s, _ := e.call(e.token(pat), "GET", base+"/audit-log", nil, ""); s != http.StatusForbidden {
		t.Errorf("without See logs: %d", s)
	}
	if s, _ := e.call(e.token(otherAdmin), "GET", base+"/audit-log", nil, ""); s != http.StatusNotFound {
		t.Errorf("another organisation's admin: %d", s)
	}
	var otherLog auditPage
	json.Unmarshal(e.must(e.token(otherAdmin), "GET", "/organisations/"+other.ID+"/audit-log", nil), &otherLog)
	if len(otherLog.Entries) != 0 {
		t.Errorf("Elsewhere sees %d of Greenfield's entries", len(otherLog.Entries))
	}

	// ── Sign-ins ───────────────────────────────────────────────────────────

	b := e.browser()
	b.post("/sign-in", map[string]string{"email": "nobody@" + domain, "password": "x"})
	b.post("/sign-in", map[string]string{"email": "vic@" + domain, "password": "wrong"})
	b.post("/sign-in", map[string]string{"email": "jo@" + domain, "password": pw + "x"}) // disabled
	ar, err := e.st.CreateAuthRequest(ctx, &store.AuthRequest{ClientID: "work", RedirectURI: "https://work.test/cb",
		Scopes: []string{"openid", "profile"}, ResponseType: "code", Prompt: []string{}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Work is turned off for everyone (above): the password is right, the app isn't allowed.
	if s, body := b.post("/sign-in", map[string]string{"email": "vic@" + domain, "password": pw,
		"authRequestID": ar.ID}); s != http.StatusForbidden {
		t.Fatalf("sign in to a turned-off app: %d %s", s, body)
	}
	e.must(adminTok, "PUT", base+"/apps/work", map[string]any{"mode": ""})
	if s, body := b.get("/flow?authRequestID=" + ar.ID); s != http.StatusOK || !strings.Contains(body, `"step":"consent"`) {
		t.Errorf("app: %d %s", s, body)
	}
	if s, body := b.post("/consent", map[string]any{"authRequestID": ar.ID}); s != http.StatusOK {
		t.Errorf("consent: %d %s", s, body)
	}

	var signIns signInPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/sign-ins", nil), &signIns)
	type row struct {
		method, email, client, reason string
		ok                            bool
	}
	got := []row{}
	for _, s := range signIns.Entries {
		client := ""
		if s.ClientName != nil {
			client = *s.ClientName
		}
		got = append(got, row{s.Method, s.Email, client, s.Reason, s.Success})
		if s.IP != "198.51.100.9" || s.UserAgent != "e2e-browser/1.0" {
			t.Errorf("ip %q ua %q", s.IP, s.UserAgent)
		}
	}
	want := []row{
		{"app", "vic@" + domain, "Keston Work", "", true},
		{"app", "vic@" + domain, "Keston Work", "app_disabled", false},
		{"password", "vic@" + domain, "Keston Work", "", true},
		{"password", "jo@" + domain, "", "disabled", false},
		{"password", "vic@" + domain, "", "wrong_password", false},
		{"password", "nobody@" + domain, "", "unknown_user", false},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("sign-ins:\n got %v\nwant %v", got, want)
	}
	var failed signInPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/sign-ins?result=failure&user="+viewer.ID, nil), &failed)
	if len(failed.Entries) != 2 {
		t.Errorf("Vic's failures: %d, want 2", len(failed.Entries))
	}
	var wrong signInPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/sign-ins?reason=unknown_user", nil), &wrong)
	if len(wrong.Entries) != 1 {
		t.Errorf("unknown_user: %d", len(wrong.Entries))
	}

	// ── Kept for a year ────────────────────────────────────────────────────

	if _, err := e.st.DB.Exec(ctx, `UPDATE audit_log SET created_at = now() - interval '366 days'
		WHERE organisation_id = $1 AND action = 'group.created'`, org.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB.Exec(ctx, `UPDATE sign_in_log SET created_at = now() - interval '366 days'
		WHERE organisation_id = $1 AND reason = 'unknown_user'`, org.ID); err != nil {
		t.Fatal(err)
	}
	e.admin.Housekeeping(ctx)
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log?action=group.created", nil), &only)
	json.Unmarshal(e.must(adminTok, "GET", base+"/sign-ins?reason=unknown_user", nil), &wrong)
	if len(only.Entries) != 0 || len(wrong.Entries) != 0 {
		t.Errorf("after a year: %d audit, %d sign-in entries left", len(only.Entries), len(wrong.Entries))
	}

	// The catalogue has the new permission.
	if !strings.Contains(string(e.must(adminTok, "GET", "/permissions", nil)), `"reports.view"`) {
		t.Errorf("reports.view isn't in the permission catalogue")
	}
}

// Keston support: what they do through a support account says so, and
// opening it is a sign-in.
func TestSupportLogs(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	const pw = "Correct-Horse-Battery-9"
	platform, err := e.st.EnsurePlatformOrganisation(ctx, "The Keston Group", "thekestongroup.test")
	if err != nil {
		t.Fatal(err)
	}
	staff, err := e.st.CreateUser(ctx, e.st.DB, store.NewUser{OrganisationID: platform.ID,
		Email: "sam" + suffix + "@thekestongroup.test", Name: "Sam Staff", Role: "global_admin",
		PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		t.Fatal(err)
	}
	domain := "school" + suffix + ".test"
	org, admin, err := e.st.CreateOrganisation(ctx, "School", domain, store.NewUser{
		Email: "head@" + domain, Name: "Head", PasswordHash: secret.HashPassword(pw)})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.SetMFAMode(ctx, org.ID, store.MFAOff) // Not testing MFA here.
	base := "/organisations/" + org.ID
	staffTok, adminTok := e.token(staff), e.token(admin)

	e.must(staffTok, "POST", base+"/support/requests", map[string]string{"reason": "Help with MFA"})
	var sup struct {
		Requests []struct{ ID string } `json:"requests"`
	}
	json.Unmarshal(e.must(adminTok, "GET", base+"/support", nil), &sup)
	e.must(adminTok, "POST", base+"/support/requests/"+sup.Requests[0].ID+"/approve", map[string]int{"days": 3})
	var open struct{ URL string }
	json.Unmarshal(e.must(staffTok, "POST", base+"/support/open", nil), &open)

	// Opening it in Keston ID.
	b := e.browser()
	b.c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, query, _ := strings.Cut(open.URL, "?")
	if s, body := b.get("/support-sign-in?" + query); s != http.StatusSeeOther {
		t.Fatalf("support sign-in: %d %s", s, body)
	}

	sa, err := e.st.SupportAccount(ctx, org.ID, staff.ID)
	if err != nil {
		t.Fatal(err)
	}
	var jo struct{ ID string }
	json.Unmarshal(e.must(e.token(sa), "POST", base+"/users", map[string]any{
		"name": "Jo", "username": "jo", "password": pw}), &jo)

	var log auditPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/audit-log", nil), &log)
	got := []string{}
	for _, r := range log.Entries {
		via := ""
		if r.SupportStaffName != nil {
			via = " via " + *r.SupportStaffName
		}
		got = append(got, r.Action+" by "+r.ActorName+via+": "+r.Summary)
	}
	want := []string{
		"user.created by Sam Staff (Keston support) via Sam Staff: Role: Member",
		"support.opened by Sam Staff: ",
		"support.allowed by Head: For 3 days",
		"support.requested by Sam Staff: Reason: Help with MFA",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit log:\n got %q\nwant %q", got, want)
	}

	var signIns signInPage
	json.Unmarshal(e.must(adminTok, "GET", base+"/sign-ins", nil), &signIns)
	if len(signIns.Entries) != 1 || signIns.Entries[0].Method != "support" || !signIns.Entries[0].Success ||
		signIns.Entries[0].SupportStaffName == nil || *signIns.Entries[0].SupportStaffName != "Sam Staff" {
		t.Errorf("support sign-in: %+v", signIns.Entries)
	}
}
