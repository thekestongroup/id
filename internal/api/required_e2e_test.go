//go:build e2e

// End-to-end tests for required actions and access passes: the real
// handlers against a real Postgres.
//
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55420/keston_id?sslmode=disable \
//	  go test -tags e2e ./internal/api/
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

const goodPassword = "correct horse battery staple"

type env struct {
	t     *testing.T
	st    *store.Store
	srv   *httptest.Server
	orgID string
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
	box, _ := secret.NewBox([32]byte{1, 2, 3})
	st := store.New(pool, box)
	cfg := &config.Config{Issuer: "http://id.test", Insecure: true, SessionTTL: time.Hour}
	a := New(st, cfg, func(context.Context, string) error { return nil })
	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", a.Routes()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	domain := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + secret.Token()[:6] + ".test"
	domain = strings.ReplaceAll(strings.ReplaceAll(domain, "_", "-"), "--", "-")
	org, _, err := st.CreateOrganisation(ctx, "Test "+t.Name(), domain, store.NewUser{
		Email: "admin@" + domain, Name: "Admin", PasswordHash: secret.HashPassword(goodPassword)})
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, st: st, srv: srv, orgID: org.ID}
}

func (e *env) user(name string) *store.User {
	e.t.Helper()
	org, _ := e.st.OrganisationByID(context.Background(), e.orgID)
	u, err := e.st.CreateUser(context.Background(), e.st.DB, store.NewUser{OrganisationID: e.orgID,
		Email: name + "@" + org.Domain, Name: name, PasswordHash: secret.HashPassword(goodPassword)})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// browser: a cookie jar, like one person's browser.
type browser struct {
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e, &http.Client{Jar: jar}}
}

func (b *browser) do(method, path string, body any, out any) int {
	b.e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, b.e.srv.URL+"/api"+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keston-ID", "1")
	res, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

type flowOut struct {
	Step     string   `json:"step"`
	Actions  []string `json:"actions"`
	Redirect string   `json:"redirect"`
	Field    string   `json:"field"`
	Message  string   `json:"message"`
}

func (b *browser) signIn(email, password string, authRequestID string) flowOut {
	b.e.t.Helper()
	var f flowOut
	if code := b.do("POST", "/sign-in", map[string]string{"email": email, "password": password,
		"authRequestID": authRequestID}, &f); code != 200 {
		b.e.t.Fatalf("sign in: %d %+v", code, f)
	}
	return f
}

func wantActions(t *testing.T, f flowOut, want ...string) {
	t.Helper()
	if f.Step != "actions" || strings.Join(f.Actions, ",") != strings.Join(want, ",") {
		t.Fatalf("want actions %v, got %+v", want, f)
	}
}

// setUpMFA goes through setup and enable, returning the secret.
func (b *browser) setUpMFA(authRequestID string) (string, flowOut) {
	t := b.e.t
	t.Helper()
	var s struct{ Secret string }
	if code := b.do("POST", "/required/mfa/setup", map[string]any{}, &s); code != 200 || s.Secret == "" {
		t.Fatalf("mfa setup: %d", code)
	}
	var out struct {
		BackupCodes []string `json:"backupCodes"`
		Flow        flowOut  `json:"flow"`
		Field       string   `json:"field"`
	}
	if code := b.do("POST", "/required/mfa/enable", map[string]string{"code": "000000",
		"authRequestID": authRequestID}, &out); code != 422 || out.Field != "code" {
		t.Fatalf("wrong code accepted: %d", code)
	}
	c, _ := totp.GenerateCode(s.Secret, time.Now())
	if code := b.do("POST", "/required/mfa/enable", map[string]string{"code": c, "authRequestID": authRequestID},
		&out); code != 200 || len(out.BackupCodes) != 10 {
		t.Fatalf("mfa enable: %d %+v", code, out)
	}
	return s.Secret, out.Flow
}

func TestPasswordChangeRequired(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user("pat")
	if err := e.st.SetPasswordChangeRequired(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	f := b.signIn(u.Email, goodPassword, "")
	wantActions(t, f, ActionPassword)

	// Not fully signed in: no account pages, no MFA endpoint.
	if code := b.do("GET", "/me", nil, nil); code != 401 {
		t.Fatalf("/me before the action: %d", code)
	}
	if code := b.do("POST", "/required/mfa/setup", map[string]any{}, nil); code != 409 {
		t.Fatalf("mfa setup not required: %d", code)
	}
	// Same as the old one, then too weak, then fine.
	var bad flowOut
	if code := b.do("POST", "/required/password", map[string]string{"new": goodPassword}, &bad); code != 422 ||
		!strings.Contains(bad.Message, "different") {
		t.Fatalf("old password accepted: %d %+v", code, bad)
	}
	if code := b.do("POST", "/required/password", map[string]string{"new": "short"}, &bad); code != 422 {
		t.Fatalf("weak password accepted: %d", code)
	}
	if code := b.do("POST", "/required/password", map[string]string{"new": "a whole new passphrase here"}, &f); code != 200 ||
		f.Step != "account" {
		t.Fatalf("new password: %d %+v", code, f)
	}
	if code := b.do("GET", "/me", nil, nil); code != 200 {
		t.Fatalf("/me after: %d", code)
	}
	st, _ := e.st.SignInState(ctx, u)
	if st.PasswordChangeRequired {
		t.Fatal("still required")
	}
	// Signing in again: the new password, no actions.
	if f := e.browser().signIn(u.Email, "a whole new passphrase here", ""); f.Step != "account" {
		t.Fatalf("second sign-in: %+v", f)
	}
}

// A signed-in session that gains an action goes back to 'actions'.
func TestRequiredLaterDemotesSession(t *testing.T) {
	e := setup(t)
	u := e.user("sam")
	b := e.browser()
	if f := b.signIn(u.Email, goodPassword, ""); f.Step != "account" {
		t.Fatalf("sign in: %+v", f)
	}
	if code := b.do("GET", "/me", nil, nil); code != 200 {
		t.Fatalf("/me: %d", code)
	}
	_ = e.st.SetPasswordChangeRequired(context.Background(), u.ID, true)
	if code := b.do("GET", "/me", nil, nil); code != 401 {
		t.Fatalf("/me after requiring: %d", code)
	}
	var f flowOut
	b.do("GET", "/flow", nil, &f)
	wantActions(t, f, ActionPassword)
}

func TestMFARequiredPolicy(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	alex, bo, cy := e.user("alex"), e.user("bo"), e.user("cy")
	office, _ := e.st.CreateGroup(ctx, e.orgID, "Office")
	staff, _ := e.st.CreateGroup(ctx, e.orgID, "Staff")
	yes, no := true, false
	_ = e.st.SetMFARequired(ctx, e.orgID, true)
	_ = e.st.SetGroupMFARequired(ctx, e.orgID, office.ID, &no)
	_ = e.st.SetGroupMFARequired(ctx, e.orgID, staff.ID, &yes)
	_ = e.st.AddGroupMember(ctx, office.ID, bo.ID) // not required: the group overrides the default
	_ = e.st.AddGroupMember(ctx, office.ID, cy.ID) // required: Staff requires it, and wins
	_ = e.st.AddGroupMember(ctx, staff.ID, cy.ID)

	for _, c := range []struct {
		u    *store.User
		want bool
	}{{alex, true}, {bo, false}, {cy, true}} {
		st, err := e.st.SignInState(ctx, c.u)
		if err != nil || st.MFARequired != c.want {
			t.Fatalf("%s: required %v, want %v (%v)", c.u.Name, st.MFARequired, c.want, err)
		}
	}
	if f := e.browser().signIn(bo.Email, goodPassword, ""); f.Step != "account" {
		t.Fatalf("bo: %+v", f)
	}

	// Alex: walked through setting up MFA, then signed in.
	b := e.browser()
	wantActions(t, b.signIn(alex.Email, goodPassword, ""), ActionMFA)
	key, f := b.setUpMFA("")
	if f.Step != "account" {
		t.Fatalf("after mfa: %+v", f)
	}
	// Next time: password, then the MFA code, then in.
	b2 := e.browser()
	if f := b2.signIn(alex.Email, goodPassword, ""); f.Step != "mfa" {
		t.Fatalf("second sign-in: %+v", f)
	}
	c, _ := totp.GenerateCode(key, time.Now())
	var after flowOut
	if code := b2.do("POST", "/mfa", map[string]string{"code": c}, &after); code != 200 || after.Step != "account" {
		t.Fatalf("mfa: %d %+v", code, after)
	}
}

func TestBothActionsBeforeTheApp(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user("dee")
	_ = e.st.SetMFARequired(ctx, e.orgID, true)
	_ = e.st.SetPasswordChangeRequired(ctx, u.ID, true)
	client := &store.Client{ID: "test-app-" + secret.Token()[:6], Name: "Test app", Publisher: "Test",
		Verification: "none", RedirectURIs: []string{"http://app.test/cb"}, RequiredScopes: []string{"openid"},
		OptionalScopes: []string{}, PostLogoutRedirectURIs: []string{}, SkipConsent: true}
	if err := e.st.UpsertClient(ctx, client, new(string)); err != nil {
		t.Fatal(err)
	}
	ar, err := e.st.CreateAuthRequest(ctx, &store.AuthRequest{ClientID: client.ID, RedirectURI: "http://app.test/cb",
		Scopes: []string{"openid"}, ResponseType: "code", Prompt: []string{}, AMR: []string{}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	wantActions(t, b.signIn(u.Email, goodPassword, ar.ID), ActionPassword, ActionMFA)
	var f flowOut
	b.do("POST", "/required/password", map[string]string{"new": "a whole new passphrase here", "authRequestID": ar.ID}, &f)
	wantActions(t, f, ActionMFA)
	if got, _ := e.st.AuthRequestByID(ctx, ar.ID); got.Done {
		t.Fatal("auth request completed before the actions")
	}
	_, f = b.setUpMFA(ar.ID)
	if f.Step != "redirect" || !strings.Contains(f.Redirect, "/authorize/callback") {
		t.Fatalf("after both: %+v", f)
	}
	if got, _ := e.st.AuthRequestByID(ctx, ar.ID); !got.Done {
		t.Fatal("auth request not completed")
	}
}

func TestPromptNoneWithActions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user("eve")
	client := &store.Client{ID: "test-app-" + secret.Token()[:6], Name: "Test app", Publisher: "Test",
		Verification: "none", RedirectURIs: []string{"http://app.test/cb"}, RequiredScopes: []string{"openid"},
		OptionalScopes: []string{}, PostLogoutRedirectURIs: []string{}, SkipConsent: true}
	if err := e.st.UpsertClient(ctx, client, new(string)); err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	b.signIn(u.Email, goodPassword, "")
	_ = e.st.SetPasswordChangeRequired(ctx, u.ID, true)
	ar, _ := e.st.CreateAuthRequest(ctx, &store.AuthRequest{ClientID: client.ID, RedirectURI: "http://app.test/cb",
		Scopes: []string{"openid"}, ResponseType: "code", Prompt: []string{"none"}, AMR: []string{}}, time.Hour)
	if ar == nil {
		t.Fatal("no auth request")
	}
	var f flowOut
	b.do("GET", "/flow?authRequestID="+ar.ID, nil, &f)
	if f.Step != "redirect" || !strings.Contains(f.Redirect, "interaction_required") {
		t.Fatalf("prompt=none: %+v", f)
	}
}

func TestAccessPass(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	u := e.user("fin")

	// Fin had MFA, then lost their phone.
	old, _ := totp.Generate(totp.GenerateOpts{Issuer: "Keston ID", AccountName: u.Email})
	_ = e.st.SetTOTP(ctx, u.ID, e.st.Box.Seal([]byte(old.Secret())))
	if err := e.st.EnableTOTP(ctx, u.ID, []string{}); err != nil {
		t.Fatal(err)
	}

	code, hash := secret.NewAccessPass()
	pass, err := e.st.CreateAccessPass(ctx, u.ID, u.ID, hash, true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(b *browser, code string) (int, flowOut) {
		var f flowOut
		n := b.do("POST", "/sign-in/access-pass", map[string]string{"email": u.Email, "code": code}, &f)
		return n, f
	}
	if n, f := signIn(e.browser(), "AAAA-BBBB-CCCC-DDDD"); n != 422 || f.Field != "code" {
		t.Fatalf("wrong pass: %d %+v", n, f)
	}
	// Typed in lower case, without dashes: still works. MFA comes next,
	// though they had it: the pass replaces their password and MFA.
	b := e.browser()
	n, f := signIn(b, strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if n != 200 {
		t.Fatalf("pass: %d %+v", n, f)
	}
	wantActions(t, f, ActionMFA)
	if code := b.do("GET", "/me", nil, nil); code != 401 {
		t.Fatalf("/me with only a pass: %d", code)
	}
	// One-time: it doesn't work again.
	if n, _ := signIn(e.browser(), code); n != 422 {
		t.Fatalf("one-time pass used twice: %d", n)
	}
	// Starting setup doesn't turn off the authenticator they had.
	b.do("POST", "/required/mfa/setup", map[string]any{}, nil)
	if got, _ := e.st.UserByID(ctx, u.ID); !got.TOTPEnabled {
		t.Fatal("old MFA turned off by starting setup")
	}
	newKey, f := b.setUpMFA("")
	if f.Step != "account" {
		t.Fatalf("after setup: %+v", f)
	}
	got, _ := e.st.UserByID(ctx, u.ID)
	k, _ := e.st.Box.Open(got.TOTPSecret)
	if string(k) != newKey {
		t.Fatal("new authenticator not in use")
	}

	// Time-limited: works more than once; revoked: doesn't.
	code2, hash2 := secret.NewAccessPass()
	pass2, _ := e.st.CreateAccessPass(ctx, u.ID, u.ID, hash2, false, time.Hour)
	for range 2 {
		if n, f := signIn(e.browser(), code2); n != 200 {
			t.Fatalf("time-limited pass: %d %+v", n, f)
		}
	}
	_ = e.st.RevokeAccessPass(ctx, u.ID, pass2.ID)
	if n, _ := signIn(e.browser(), code2); n != 422 {
		t.Fatalf("revoked pass: %d", n)
	}
	list, _ := e.st.AccessPasses(ctx, u.ID)
	if len(list) != 2 || list[0].Usable(time.Now()) || list[1].ID != pass.ID || list[1].Usable(time.Now()) {
		t.Fatalf("passes: %+v", list)
	}

	// Expired passes don't work.
	code3, hash3 := secret.NewAccessPass()
	p3, _ := e.st.CreateAccessPass(ctx, u.ID, u.ID, hash3, false, time.Hour)
	_, _ = e.st.DB.Exec(ctx, `UPDATE access_passes SET expires_at = now() - interval '1 minute' WHERE id = $1`, p3.ID)
	if n, _ := signIn(e.browser(), code3); n != 422 {
		t.Fatalf("expired pass: %d", n)
	}
}
