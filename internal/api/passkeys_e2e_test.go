//go:build e2e

// End-to-end tests for passkeys, against a real Postgres and the real
// handlers, with a virtual authenticator:
//
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55430/keston_id?sslmode=disable \
//		go test -tags e2e ./internal/...
package api

import (
	"bytes"
	"context"
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

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/principal"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

const testIssuer = "http://id.keston.localhost:4444"

type harness struct {
	t      *testing.T
	st     *store.Store
	srv    *httptest.Server
	client *http.Client
}

func newHarness(t *testing.T) (*harness, *store.User) {
	t.Helper()
	dsn := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("KESTON_ID_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
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
	suffix := fmt.Sprint(time.Now().UnixNano())
	_, user, err := st.CreateOrganisation(ctx, "Passkey Test "+suffix, "pk"+suffix+".test", store.NewUser{
		Email: "ada@pk" + suffix + ".test", Name: "Ada", Role: "global_admin",
		PasswordHash: secret.HashPassword("correct horse battery"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Issuer: testIssuer, Insecure: true, SessionTTL: time.Hour}
	a := New(st, cfg, func(context.Context, string) error { return nil })
	// As server.go mounts them: the sign-in flow at /api, your account at
	// /v1/me (the session cookie; no access tokens in these tests).
	r := chi.NewRouter()
	r.Mount("/api", a.Routes())
	r.With(principal.Middleware(st, nil, a.CookieSession)).Mount("/v1/me", a.MeRoutes())
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	h := &harness{t: t, st: st, srv: srv}
	h.newBrowser()
	return h, user
}

// newBrowser: a fresh cookie jar, as a different browser.
func (h *harness) newBrowser() {
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar}
}

func (h *harness) do(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keston-ID", "1")
	res, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	} else if len(raw) > 0 && raw[0] == '[' {
		var list []any
		_ = json.Unmarshal(raw, &list)
		out["list"] = list
	}
	return res.StatusCode, out
}

func (h *harness) must(want int, method, path string, body any) map[string]any {
	h.t.Helper()
	got, out := h.do(method, path, body)
	if got != want {
		h.t.Fatalf("%s %s: status %d, want %d: %v", method, path, got, want, out)
	}
	return out
}

func (h *harness) signInPassword(u *store.User) map[string]any {
	return h.must(200, "POST", "/api/sign-in", map[string]string{"email": u.Email, "password": "correct horse battery"})
}

var rp = virtualwebauthn.RelyingParty{ID: "id.keston.localhost", Name: "Keston ID", Origin: testIssuer}

func optionsJSON(t *testing.T, res map[string]any) string {
	t.Helper()
	b, err := json.Marshal(res["options"])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// register adds a passkey from the virtual authenticator.
func (h *harness) register(auth *virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, name string,
	body any) map[string]any {
	h.t.Helper()
	res := h.must(200, "POST", "/v1/me/passkeys/options", body)
	opts, err := virtualwebauthn.ParseAttestationOptions(optionsJSON(h.t, res))
	if err != nil {
		h.t.Fatal(err)
	}
	if opts.RelyingPartyID != rp.ID {
		h.t.Fatalf("rp id %q, want %q", opts.RelyingPartyID, rp.ID)
	}
	resp := virtualwebauthn.CreateAttestationResponse(rp, *auth, cred, *opts)
	out := h.must(201, "POST", "/v1/me/passkeys", map[string]any{
		"ceremony": res["ceremony"], "name": name, "credential": json.RawMessage(resp)})
	auth.AddCredential(cred)
	return out
}

func assert(h *harness, auth virtualwebauthn.Authenticator, cred virtualwebauthn.Credential, res map[string]any) json.RawMessage {
	h.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(optionsJSON(h.t, res))
	if err != nil {
		h.t.Fatal(err)
	}
	return json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, auth, cred, *opts))
}

func TestPasskeys(t *testing.T) {
	h, user := newHarness(t)
	ctx := context.Background()

	// No MFA yet: a password signs in fully.
	if step := h.signInPassword(user)["step"]; step != "account" {
		t.Fatalf("step %v, want account", step)
	}

	// Add a passkey (just signed in, so no password needed).
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: userHandle(user.ID), BackupEligible: true})
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	added := h.register(&auth, cred, "  MacBook  ", nil)
	if added["name"] != "MacBook" || added["synced"] != true {
		t.Fatalf("added %v", added)
	}
	id := added["id"].(string)

	me := h.must(200, "GET", "/v1/me", nil)
	sec := me["security"].(map[string]any)
	if sec["mfa"] != true || sec["authenticatorApp"] != false || sec["passkeys"] != float64(1) {
		t.Fatalf("security %v", sec)
	}

	// The same authenticator can't be added twice (it's excluded), and a
	// ceremony can't be used twice.
	res := h.must(200, "POST", "/v1/me/passkeys/options", nil)
	if ex := res["options"].(map[string]any)["excludeCredentials"].([]any); len(ex) != 1 {
		t.Fatalf("excludeCredentials %v", ex)
	}

	// Rename; list shows it, not used yet.
	h.must(200, "PATCH", "/v1/me/passkeys/"+id, map[string]string{"name": "Work laptop"})
	got, out := h.do("PATCH", "/v1/me/passkeys/"+id, map[string]string{"name": " "})
	if got != 422 {
		t.Fatalf("empty name: %d %v", got, out)
	}
	list := h.must(200, "GET", "/v1/me/passkeys", nil)["list"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["name"] != "Work laptop" || list[0].(map[string]any)["lastUsedAt"] != nil {
		t.Fatalf("list %v", list)
	}

	// A passkey counts as MFA: the password now leads to the MFA step,
	// which offers the passkey (not an authenticator code).
	h.must(200, "POST", "/api/sign-out", nil)
	f := h.signInPassword(user)
	if f["step"] != "mfa" {
		t.Fatalf("step %v, want mfa", f["step"])
	}
	if m := f["mfa"].(map[string]any); m["passkey"] != true || m["app"] != false {
		t.Fatalf("mfa methods %v", m)
	}
	// Not signed in fully yet.
	h.must(401, "GET", "/v1/me", nil)
	// An authenticator code doesn't work without an authenticator app.
	got, _ = h.do("POST", "/api/mfa", map[string]string{"code": "123456"})
	if got != 422 {
		t.Fatalf("totp without app: %d", got)
	}
	res = h.must(200, "POST", "/api/mfa/passkey/options", nil)
	allow := res["options"].(map[string]any)["allowCredentials"].([]any)
	if len(allow) != 1 {
		t.Fatalf("allowCredentials %v", allow)
	}
	answer := assert(h, auth, cred, res)
	f = h.must(200, "POST", "/api/mfa/passkey", map[string]any{"ceremony": res["ceremony"], "credential": answer})
	if f["step"] != "account" {
		t.Fatalf("after passkey mfa: %v", f)
	}
	// The ceremony is used up.
	got, _ = h.do("POST", "/api/mfa/passkey", map[string]any{"ceremony": res["ceremony"], "credential": answer})
	if got != 401 { // the session is verified now, so it's past its MFA step
		t.Fatalf("replay: %d", got)
	}
	h.must(200, "GET", "/v1/me", nil)
	list = h.must(200, "GET", "/v1/me/passkeys", nil)["list"].([]any)
	if list[0].(map[string]any)["lastUsedAt"] == nil {
		t.Fatal("lastUsedAt not set")
	}

	// Passwordless: a new browser signs in with the passkey alone.
	h.newBrowser()
	cred.Counter++
	res = h.must(200, "POST", "/api/sign-in/passkey/options", nil)
	if uv := res["options"].(map[string]any)["userVerification"]; uv != "required" {
		t.Fatalf("userVerification %v", uv)
	}
	answer = assert(h, auth, cred, res)
	f = h.must(200, "POST", "/api/sign-in/passkey", map[string]any{"ceremony": res["ceremony"], "credential": answer})
	if f["step"] != "account" || f["user"].(map[string]any)["id"] != user.ID {
		t.Fatalf("passwordless: %v", f)
	}
	h.must(200, "GET", "/v1/me", nil)
	// Replaying the same answer fails: the ceremony is gone.
	got, _ = h.do("POST", "/api/sign-in/passkey", map[string]any{"ceremony": res["ceremony"], "credential": answer})
	if got != 410 {
		t.Fatalf("replay passwordless: %d", got)
	}
	sessions, _ := h.st.SessionsForUser(ctx, user.ID)
	var amr []string
	for _, s := range sessions {
		if s.Stage == "verified" && strings.Join(s.AMR, ",") == "hwk,mfa" {
			amr = s.AMR
		}
	}
	if amr == nil {
		t.Fatal("no session with amr hwk,mfa")
	}

	// A passkey that isn't on any account doesn't sign in.
	h.newBrowser()
	stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	res = h.must(200, "POST", "/api/sign-in/passkey/options", nil)
	got, _ = h.do("POST", "/api/sign-in/passkey", map[string]any{"ceremony": res["ceremony"],
		"credential": assert(h, auth, stranger, res)})
	if got != 401 {
		t.Fatalf("unknown passkey: %d", got)
	}
	// A disabled account can't sign in with its passkey.
	if err := h.st.SetUserStatus(ctx, user.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	cred.Counter++
	res = h.must(200, "POST", "/api/sign-in/passkey/options", nil)
	got, _ = h.do("POST", "/api/sign-in/passkey", map[string]any{"ceremony": res["ceremony"],
		"credential": assert(h, auth, cred, res)})
	if got != 401 {
		t.Fatalf("disabled account: %d", got)
	}
	if err := h.st.SetUserStatus(ctx, user.ID, "active"); err != nil {
		t.Fatal(err)
	}

	// Adding another needs a recent sign-in: after 10 minutes, the password.
	cred.Counter++
	res = h.must(200, "POST", "/api/sign-in/passkey/options", nil)
	h.must(200, "POST", "/api/sign-in/passkey", map[string]any{"ceremony": res["ceremony"],
		"credential": assert(h, auth, cred, res)})
	if _, err := h.st.DB.Exec(ctx, `UPDATE sessions SET auth_time = now() - interval '11 minutes' WHERE user_id = $1`,
		user.ID); err != nil {
		t.Fatal(err)
	}
	got, out = h.do("POST", "/v1/me/passkeys/options", nil)
	if got != 403 || out["error"] != "reauthenticate" {
		t.Fatalf("stale sign-in: %d %v", got, out)
	}
	got, out = h.do("POST", "/v1/me/passkeys/options", map[string]string{"password": "wrong"})
	if got != 422 || out["field"] != "password" {
		t.Fatalf("wrong password: %d %v", got, out)
	}
	key2 := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	auth2 := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: userHandle(user.ID)})
	added2 := h.register(&auth2, key2, "YubiKey", map[string]string{"password": "correct horse battery"})
	if added2["synced"] != false {
		t.Fatalf("security key synced: %v", added2)
	}

	// Remove both: MFA is off again, and the password signs in fully.
	h.must(204, "DELETE", "/v1/me/passkeys/"+id, nil)
	h.must(404, "DELETE", "/v1/me/passkeys/"+id, nil)
	h.must(204, "DELETE", "/v1/me/passkeys/"+added2["id"].(string), nil)
	if sec := h.must(200, "GET", "/v1/me", nil)["security"].(map[string]any); sec["mfa"] != false {
		t.Fatalf("security after removing %v", sec)
	}
	h.newBrowser()
	if step := h.signInPassword(user)["step"]; step != "account" {
		t.Fatalf("step %v, want account", step)
	}
}

// Someone else's passkey can't be renamed or removed.
func TestPasskeysAreYourOwn(t *testing.T) {
	h, user := newHarness(t)
	ctx := context.Background()
	other, err := h.st.CreateUser(ctx, h.st.DB, store.NewUser{OrganisationID: user.OrganisationID,
		Email: "bob@" + strings.Split(user.Email, "@")[1], Name: "Bob", PasswordHash: secret.HashPassword("correct horse battery")})
	if err != nil {
		t.Fatal(err)
	}
	h.signInPassword(other)
	auth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: userHandle(other.ID)})
	added := h.register(&auth, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), "Bob's key", nil)

	h.newBrowser()
	h.signInPassword(user)
	h.must(404, "PATCH", "/v1/me/passkeys/"+added["id"].(string), map[string]string{"name": "Mine now"})
	h.must(404, "DELETE", "/v1/me/passkeys/"+added["id"].(string), nil)
	if n, _ := h.st.PasskeyCount(ctx, other.ID); n != 1 {
		t.Fatalf("bob has %d passkeys", n)
	}
}
