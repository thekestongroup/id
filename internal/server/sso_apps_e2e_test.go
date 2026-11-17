//go:build e2e

// End-to-end tests for organisations' own SSO apps (OpenID Connect and
// SAML), against a real Postgres and the real handlers:
//
//	docker run -d --name pg-sso-apps -e POSTGRES_USER=keston -e POSTGRES_PASSWORD=keston \
//	  -e POSTGRES_DB=keston_id -p 55450:5432 postgres:17-alpine
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55450/keston_id?sslmode=disable \
//	  go test -tags e2e ./internal/server/
package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/pquerna/otp/totp"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/oidcstore"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/server"
	"github.com/thekestongroup/id/internal/store"
)

const password = "correct horse battery staple 42"

type env struct {
	t      *testing.T
	srv    *httptest.Server
	st     *store.Store
	issuer string
}

func setup(t *testing.T) *env {
	t.Helper()
	dbURL := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://keston:keston@localhost:55450/keston_id?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], "keston-id-e2e-test-secret-key!!!")
	box, _ := secret.NewBox(key)
	st := store.New(pool, box)

	srv := httptest.NewUnstartedServer(nil)
	// localhost, not 127.0.0.1: passkeys need a domain for their RP ID.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	issuer := "http://localhost:" + port
	cfg := &config.Config{Issuer: issuer, SecretKey: key, Insecure: true, AccessTokenTTL: 15 * time.Minute,
		IDTokenTTL: time.Hour, RefreshTokenTTL: time.Hour, SessionTTL: time.Hour, AuthRequestTTL: 30 * time.Minute}
	storage := oidcstore.New(st, cfg)
	if err := storage.EnsureSigningKey(ctx); err != nil {
		t.Fatal(err)
	}
	h, err := server.New(cfg, st, storage, fstest.MapFS{"index.html": {Data: []byte("web")}})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)

	// Keston Admin's client, as deploy/clients.json has it (on localhost).
	if err := st.UpsertClient(ctx, &store.Client{ID: "admin", Name: "Keston Admin", Publisher: "The Keston Group",
		Verification: "owned", RedirectURIs: []string{"http://localhost/admin/callback"},
		PostLogoutRedirectURIs: []string{}, RequiredScopes: []string{"openid", "profile", "email"},
		OptionalScopes: []string{}, SkipConsent: true, DevMode: true}, new(string)); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, srv: srv, st: st, issuer: issuer}
}

func (e *env) org(name, domain string) (*store.Organisation, *store.User) {
	e.t.Helper()
	org, admin, err := e.st.CreateOrganisation(context.Background(), name, domain, store.NewUser{
		Email: "admin@" + domain, Name: "Ada Admin", PasswordHash: secret.HashPassword(password)})
	if err != nil {
		e.t.Fatal(err)
	}
	_ = e.st.SetMFAMode(context.Background(), org.ID, store.MFAOff) // Not testing MFA here.
	return org, admin
}

func (e *env) user(orgID, email, name string) *store.User {
	e.t.Helper()
	u, err := e.st.CreateUser(context.Background(), e.st.DB, store.NewUser{OrganisationID: orgID, Email: email,
		Name: name, PasswordHash: secret.HashPassword(password)})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// browser: a cookie jar that doesn't follow redirects.
type browser struct {
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e, &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}}
}

func (b *browser) do(method, rawURL string, body any, header map[string]string) (*http.Response, []byte) {
	b.e.t.Helper()
	if strings.HasPrefix(rawURL, "/") {
		rawURL = b.e.issuer + rawURL
	}
	var r io.Reader
	contentType := ""
	switch v := body.(type) {
	case nil:
	case url.Values:
		r, contentType = strings.NewReader(v.Encode()), "application/x-www-form-urlencoded"
	default:
		data, _ := json.Marshal(v)
		r, contentType = bytes.NewReader(data), "application/json"
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		b.e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

type flow struct {
	Step     string `json:"step"`
	Redirect string `json:"redirect"`
	Message  string `json:"message"`
}

// signIn through the web UI's API, for the auth request a redirect to
// /sign-in names.
func (b *browser) signIn(signInURL, email string) (flow, int) {
	b.e.t.Helper()
	u, _ := url.Parse(signInURL)
	resp, data := b.do("POST", "/api/sign-in", map[string]string{"email": email, "password": password,
		"authRequestID": u.Query().Get("authRequestID")}, map[string]string{"X-Keston-ID": "1"})
	var f flow
	_ = json.Unmarshal(data, &f)
	return f, resp.StatusCode
}

func pkce() (verifier, challenge string) {
	verifier = secret.Token()
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// codeFlow: a full authorisation code flow with PKCE, signing in as email.
// Returns the token response, or the flow error.
func (b *browser) codeFlow(clientID, clientSecret, redirectURI, scope, email string) (map[string]any, *flow) {
	t := b.e.t
	t.Helper()
	verifier, challenge := pkce()
	q := url.Values{"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {scope}, "state": {"st"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	resp, data := b.do("GET", "/authorize?"+q.Encode(), nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %s", resp.StatusCode, data)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/sign-in?authRequestID=") {
		t.Fatalf("authorize went to %s", loc)
	}
	f, status := b.signIn(loc, email)
	if f.Step != "redirect" {
		return nil, &flow{Step: f.Step, Message: fmt.Sprintf("%d %s", status, f.Message)}
	}
	resp, data = b.do("GET", f.Redirect, nil, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d %s", resp.StatusCode, data)
	}
	back, _ := url.Parse(resp.Header.Get("Location"))
	code := back.Query().Get("code")
	if code == "" || back.Query().Get("state") != "st" {
		t.Fatalf("no code: %s", back)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"code_verifier": {verifier}, "client_id": {clientID}}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	resp, data = b.do("POST", "/oauth/token", form, nil)
	if resp.StatusCode != http.StatusOK {
		return nil, &flow{Step: "token", Message: fmt.Sprintf("%d %s", resp.StatusCode, data)}
	}
	var tok map[string]any
	_ = json.Unmarshal(data, &tok)
	return tok, nil
}

func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(data, &c)
	return c
}

func audience(c map[string]any) []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := []string{}
		for _, x := range v {
			out = append(out, x.(string))
		}
		return out
	}
	return nil
}

// adminAPI: a Keston Admin session for email.
type adminAPI struct {
	b     *browser
	token string
	org   string
}

func (e *env) admin(email, orgID string) *adminAPI {
	b := e.browser()
	tok, f := b.codeFlow("admin", "", "http://localhost/admin/callback", "openid profile email", email)
	if f != nil {
		e.t.Fatalf("admin sign-in: %+v", f)
	}
	return &adminAPI{b: b, token: tok["access_token"].(string), org: orgID}
}

func (a *adminAPI) call(method, path string, body any, out any) int {
	a.b.e.t.Helper()
	resp, data := a.b.do(method, "/v1/organisations/"+a.org+path, body,
		map[string]string{"Authorization": "Bearer " + a.token})
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil && resp.StatusCode < 300 {
			a.b.e.t.Fatalf("%s %s: %s", method, path, data)
		}
	}
	if resp.StatusCode >= 400 && out == nil {
		a.b.e.t.Logf("%s %s: %d %s", method, path, resp.StatusCode, data)
	}
	return resp.StatusCode
}

type ownApp struct {
	App struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Protocol string `json:"protocol"`
		OIDC     *struct {
			Type      string   `json:"type"`
			ClientID  string   `json:"clientId"`
			HasSecret bool     `json:"hasSecret"`
			Scopes    []string `json:"scopes"`
		} `json:"oidc"`
		SAML *struct {
			EntityID string `json:"entityId"`
			ACSURL   string `json:"acsUrl"`
			IdP      struct {
				MetadataURL string `json:"metadataUrl"`
				SSOURL      string `json:"ssoUrl"`
				StartURL    string `json:"startUrl"`
				Certificate string `json:"certificate"`
			} `json:"idp"`
		} `json:"saml"`
	} `json:"app"`
	ClientSecret string `json:"clientSecret"`
	Field        string `json:"field"`
	Message      string `json:"message"`
}

// ── OpenID Connect ───────────────────────────────────────────────────────

func TestOrganisationOIDCApps(t *testing.T) {
	e := setup(t)
	org, admin := e.org("Greenfield School", "greenfield.sch.uk")
	other, _ := e.org("Hillside School", "hillside.sch.uk")
	member := e.user(org.ID, "sam@greenfield.sch.uk", "Sam Student")
	outsider := e.user(other.ID, "olly@hillside.sch.uk", "Olly Outsider")
	api := e.admin(admin.Email, org.ID)

	// Checks: name, type, redirect URIs.
	var bad ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "oidc", "name": "Library", "type": "web",
		"redirectUris": []string{"http://library.example/cb"}}, &bad); s != 422 || bad.Field != "redirectUris" {
		t.Fatalf("http redirect accepted: %d %+v", s, bad)
	}
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "oidc", "name": "Library", "type": "web",
		"redirectUris": []string{"com.example.app:/cb"}}, &bad); s != 422 {
		t.Fatalf("custom scheme accepted for a web app: %d", s)
	}

	// A web app: the secret is shown once.
	var web ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "oidc", "name": "Library", "type": "web",
		"redirectUris": []string{"https://library.example/cb"}, "scopes": []string{"profile", "email"},
		"logoUrl": "https://library.example/logo.png"}, &web); s != 201 || web.ClientSecret == "" ||
		!web.App.OIDC.HasSecret {
		t.Fatalf("create web app: %d %+v", s, web)
	}
	var again ownApp
	api.call("GET", "/own-apps/"+web.App.ID, nil, &again)
	if again.ClientSecret != "" || again.App.Name != "Library" {
		t.Fatalf("get: %+v", again)
	}

	// Its users sign in with no consent prompt; the tokens have no org/perms
	// claims, and only the app as their audience.
	tok, f := e.browser().codeFlow(web.App.ID, web.ClientSecret, "https://library.example/cb",
		"openid profile email", member.Email)
	if f != nil {
		t.Fatalf("member sign-in: %+v", f)
	}
	access := jwtClaims(t, tok["access_token"].(string))
	for _, claim := range []string{"org", "perms", "platform_admin"} {
		if _, ok := access[claim]; ok {
			t.Errorf("access token has %q: %v", claim, access)
		}
	}
	if aud := audience(access); !slices.Equal(aud, []string{web.App.ID}) {
		t.Errorf("access token audience %v", aud)
	}
	id := jwtClaims(t, tok["id_token"].(string))
	if id["email"] != member.Email || id["name"] != member.Name {
		t.Errorf("id token: %v", id)
	}
	if _, ok := id["org"]; ok {
		t.Errorf("id token has org: %v", id)
	}

	// Another organisation's users can't.
	if _, f := e.browser().codeFlow(web.App.ID, web.ClientSecret, "https://library.example/cb", "openid",
		outsider.Email); f == nil || !strings.HasPrefix(f.Message, "403") {
		t.Fatalf("outsider got in: %+v", f)
	}
	// …nor do they see it among their organisation's apps.
	outAdmin := e.admin("admin@hillside.sch.uk", other.ID)
	var otherApps struct {
		Apps []struct {
			ID string `json:"id"`
		} `json:"apps"`
	}
	outAdmin.call("GET", "/apps", nil, &otherApps)
	for _, a := range otherApps.Apps {
		if a.ID == web.App.ID {
			t.Fatal("another organisation sees the app on its Apps page")
		}
	}
	if s := outAdmin.call("PUT", "/apps/"+web.App.ID, map[string]string{"mode": "forced"}, nil); s != 404 {
		t.Fatalf("another organisation set access: %d", s)
	}
	if s := outAdmin.call("GET", "/own-apps/"+web.App.ID, nil, nil); s != 404 {
		t.Fatalf("another organisation read it: %d", s)
	}

	// It's on the Apps page, and Disabled stops sign-in.
	var apps struct {
		Apps []struct {
			ID       string `json:"id"`
			Own      bool   `json:"own"`
			Protocol string `json:"protocol"`
		} `json:"apps"`
	}
	api.call("GET", "/apps", nil, &apps)
	if !slices.ContainsFunc(apps.Apps, func(a struct {
		ID       string `json:"id"`
		Own      bool   `json:"own"`
		Protocol string `json:"protocol"`
	}) bool {
		return a.ID == web.App.ID && a.Own && a.Protocol == "oidc"
	}) {
		t.Fatalf("not on the Apps page: %+v", apps)
	}
	if s := api.call("PUT", "/apps/"+web.App.ID, map[string]string{"mode": "disabled"}, nil); s != 204 {
		t.Fatalf("disable: %d", s)
	}
	if _, f := e.browser().codeFlow(web.App.ID, web.ClientSecret, "https://library.example/cb", "openid",
		member.Email); f == nil || !strings.HasPrefix(f.Message, "403") {
		t.Fatalf("disabled app let them in: %+v", f)
	}
	api.call("PUT", "/apps/"+web.App.ID, map[string]string{"mode": ""}, nil)

	// A new secret: the old one stops working.
	var rotated ownApp
	if s := api.call("POST", "/own-apps/"+web.App.ID+"/secret", nil, &rotated); s != 200 ||
		rotated.ClientSecret == "" || rotated.ClientSecret == web.ClientSecret {
		t.Fatalf("new secret: %d %+v", s, rotated)
	}
	if _, f := e.browser().codeFlow(web.App.ID, rotated.ClientSecret, "https://library.example/cb", "openid",
		member.Email); f != nil {
		t.Fatalf("new secret: %+v", f)
	}
	if _, f := e.browser().codeFlow(web.App.ID, web.ClientSecret, "https://library.example/cb", "openid",
		member.Email); f == nil || f.Step != "token" {
		t.Fatalf("old secret still works: %+v", f)
	}

	// A single-page or mobile app: PKCE, no secret, its own scheme allowed.
	var spa ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "oidc", "name": "Timetable", "type": "native",
		"redirectUris": []string{"uk.sch.greenfield.timetable:/callback", "https://timetable.example/cb"}},
		&spa); s != 201 || spa.ClientSecret != "" || spa.App.OIDC.HasSecret {
		t.Fatalf("create spa: %d %+v", s, spa)
	}
	if _, f := e.browser().codeFlow(spa.App.ID, "", "uk.sch.greenfield.timetable:/callback", "openid",
		member.Email); f != nil {
		t.Fatalf("spa sign-in: %+v", f)
	}
	if s := api.call("POST", "/own-apps/"+spa.App.ID+"/secret", nil, nil); s != 409 {
		t.Fatalf("spa secret: %d", s)
	}

	// Edit and delete.
	var edited ownApp
	if s := api.call("PATCH", "/own-apps/"+spa.App.ID, map[string]any{"name": "Timetables",
		"scopes": []string{"email"}}, &edited); s != 200 || edited.App.Name != "Timetables" ||
		!slices.Equal(edited.App.OIDC.Scopes, []string{"openid", "email"}) {
		t.Fatalf("edit: %d %+v", s, edited)
	}
	if s := api.call("DELETE", "/own-apps/"+spa.App.ID, nil, nil); s != 204 {
		t.Fatalf("delete: %d", s)
	}
	if s := api.call("GET", "/own-apps/"+spa.App.ID, nil, nil); s != 404 {
		t.Fatalf("deleted app still there: %d", s)
	}

	// Without "Set app access": no.
	g, _ := e.st.CreateGroup(context.Background(), org.ID, "Office")
	_ = e.st.SetGroupPermissions(context.Background(), g.ID, []string{store.PermViewUsers})
	_ = e.st.AddGroupMember(context.Background(), g.ID, member.ID)
	if s := e.admin(member.Email, org.ID).call("GET", "/own-apps", nil, nil); s != 403 {
		t.Fatalf("without apps.manage: %d", s)
	}
}

// ── SAML ─────────────────────────────────────────────────────────────────

func testSP(t *testing.T) *saml.ServiceProvider {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	acs, _ := url.Parse("https://sp.example/saml/acs")
	md, _ := url.Parse("https://sp.example/saml/metadata")
	return &saml.ServiceProvider{EntityID: md.String(), Key: key, Certificate: cert, AcsURL: *acs,
		MetadataURL: *md, AuthnNameIDFormat: saml.EmailAddressNameIDFormat}
}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// postedResponse: the SAMLResponse and RelayState in the auto-posting form.
func postedResponse(t *testing.T, page []byte) ([]byte, string) {
	t.Helper()
	fields := map[string]string{}
	for _, m := range formField.FindAllSubmatch(page, -1) {
		fields[string(m[1])] = html.UnescapeString(string(m[2]))
	}
	if fields["SAMLResponse"] == "" {
		t.Fatalf("no SAMLResponse in %s", page)
	}
	data, err := base64.StdEncoding.DecodeString(fields["SAMLResponse"])
	if err != nil {
		t.Fatal(err)
	}
	return data, fields["RelayState"]
}

func attrs(a *saml.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				out[at.Name] = append(out[at.Name], v.Value)
			}
		}
	}
	return out
}

func TestSAMLApps(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	org, admin := e.org("Greenfield School", "greenfield.sch.uk")
	other, _ := e.org("Hillside School", "hillside.sch.uk")
	member := e.user(org.ID, "sam@greenfield.sch.uk", "Sam Taylor Smith")
	outsider := e.user(other.ID, "olly@hillside.sch.uk", "Olly Outsider")
	g, _ := e.st.CreateGroup(ctx, org.ID, "Year 7")
	_ = e.st.AddGroupMember(ctx, g.ID, member.ID)
	api := e.admin(admin.Email, org.ID)

	// MFA on for the member.
	key, _ := totp.Generate(totp.GenerateOpts{Issuer: "Keston ID", AccountName: member.Email})
	_ = e.st.SetTOTP(ctx, member.ID, e.st.Box.Seal([]byte(key.Secret())))
	_ = e.st.EnableTOTP(ctx, member.ID, []string{})

	sp := testSP(t)
	spMetadata, _ := xml.Marshal(sp.Metadata())

	// Entity ID and ACS URL typed in: checks.
	var bad ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "saml", "name": "Typed",
		"entityId": "urn:typed", "acsUrl": "http://typed.example/acs"}, &bad); s != 422 || bad.Field != "acsUrl" {
		t.Fatalf("http ACS accepted: %d %+v", s, bad)
	}
	var typed ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "saml", "name": "Typed",
		"entityId": "urn:typed", "acsUrl": "https://typed.example/acs"}, &typed); s != 201 ||
		typed.App.SAML.ACSURL != "https://typed.example/acs" {
		t.Fatalf("typed: %d %+v", s, typed)
	}
	// Metadata pasted in.
	var app ownApp
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "saml", "name": "Learning Portal",
		"metadataXml": string(spMetadata)}, &app); s != 201 || app.App.SAML.EntityID != sp.EntityID ||
		app.App.SAML.ACSURL != sp.AcsURL.String() {
		t.Fatalf("metadata: %d %+v", s, app)
	}
	// Metadata from a URL.
	mdSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(spMetadata)
	}))
	defer mdSrv.Close()
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "saml", "name": "From URL",
		"metadataUrl": mdSrv.URL}, &bad); s != 422 || bad.Field != "metadataUrl" {
		t.Fatalf("private metadata URL fetched (or other error): %d %+v", s, bad)
	}
	// The same entity ID twice in one organisation: no.
	if s := api.call("POST", "/own-apps", map[string]any{"protocol": "saml", "name": "Again",
		"metadataXml": string(spMetadata)}, &bad); s != 422 || bad.Field != "entityId" {
		t.Fatalf("duplicate entity ID: %d %+v", s, bad)
	}

	// The IdP metadata the app is given.
	b := e.browser()
	resp, data := b.do("GET", app.App.SAML.IdP.MetadataURL, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("idp metadata: %d %s", resp.StatusCode, data)
	}
	idpMD, err := samlsp.ParseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if idpMD.EntityID != app.App.SAML.IdP.MetadataURL {
		t.Fatalf("idp entity ID %q", idpMD.EntityID)
	}
	sp.IDPMetadata = idpMD

	// SP-initiated: the request goes through sign-in and MFA first.
	authURL, err := sp.MakeRedirectAuthenticationRequest("relay-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(authURL.String(), app.App.SAML.IdP.SSOURL) {
		t.Fatalf("SSO URL %s", authURL)
	}
	resp, data = b.do("GET", authURL.String(), nil, nil)
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/sign-in?authRequestID=") {
		t.Fatalf("sso: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), data)
	}
	signIn := resp.Header.Get("Location")
	f, _ := b.signIn(signIn, member.Email)
	if f.Step != "mfa" {
		t.Fatalf("expected MFA, got %+v", f)
	}
	authReqID, _ := url.Parse(signIn)
	id := authReqID.Query().Get("authRequestID")
	// Not before MFA.
	if resp, _ := b.do("GET", "/saml/callback?id="+id, nil, nil); resp.StatusCode < 400 {
		t.Fatalf("callback before MFA: %d", resp.StatusCode)
	}
	code, _ := totp.GenerateCode(key.Secret(), time.Now())
	resp, data = b.do("POST", "/api/mfa", map[string]string{"code": code, "authRequestID": id},
		map[string]string{"X-Keston-ID": "1"})
	_ = json.Unmarshal(data, &f)
	if f.Step != "redirect" || !strings.Contains(f.Redirect, "/saml/callback?id=") {
		t.Fatalf("after MFA: %d %s", resp.StatusCode, data)
	}
	// Another browser can't collect the response.
	if resp, _ := e.browser().do("GET", f.Redirect, nil, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("another browser got the response: %d", resp.StatusCode)
	}
	resp, page := b.do("GET", f.Redirect, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("callback: %d %s", resp.StatusCode, page)
	}
	samlResp, relay := postedResponse(t, page)
	if relay != "relay-1" {
		t.Errorf("relay state %q", relay)
	}
	reqID := regexp.MustCompile(`InResponseTo="([^"]+)"`).FindSubmatch(samlResp)
	if reqID == nil {
		t.Fatalf("no InResponseTo: %s", samlResp)
	}
	assertion, err := sp.ParseXMLResponse(samlResp, []string{string(reqID[1])}, sp.AcsURL)
	if err != nil {
		t.Fatalf("SP rejected the response: %v", err)
	}
	if assertion.Subject.NameID.Value != member.Email ||
		assertion.Subject.NameID.Format != string(saml.EmailAddressNameIDFormat) {
		t.Errorf("NameID %+v", assertion.Subject.NameID)
	}
	got := attrs(assertion)
	want := map[string][]string{"email": {member.Email}, "name": {"Sam Taylor Smith"}, "given_name": {"Sam"},
		"family_name": {"Taylor Smith"}, "groups": {"Year 7"}}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Errorf("attribute %s = %v, want %v", k, got[k], v)
		}
	}
	if !bytes.Contains(samlResp, []byte("<ds:Signature")) {
		t.Error("response not signed")
	}
	// Used once.
	if resp, _ := b.do("GET", f.Redirect, nil, nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("callback replayed: %d", resp.StatusCode)
	}

	// IdP-initiated, already signed in: straight to the app.
	resp, _ = b.do("GET", app.App.SAML.IdP.StartURL+"?RelayState=home", nil, nil)
	signIn = resp.Header.Get("Location")
	resp, data = b.do("GET", "/api/flow?authRequestID="+mustQuery(signIn, "authRequestID"), nil, nil)
	_ = json.Unmarshal(data, &f)
	if f.Step != "redirect" {
		t.Fatalf("idp-initiated flow: %s", data)
	}
	_, page = b.do("GET", f.Redirect, nil, nil)
	samlResp, relay = postedResponse(t, page)
	sp.AllowIDPInitiated = true
	if assertion, err = sp.ParseXMLResponse(samlResp, nil, sp.AcsURL); err != nil {
		t.Fatalf("SP rejected the IdP-initiated response: %v", err)
	}
	if relay != "home" || assertion.Subject.NameID.Value != member.Email {
		t.Errorf("idp-initiated: relay %q, NameID %q", relay, assertion.Subject.NameID.Value)
	}

	// Another organisation's users can't.
	ob := e.browser()
	authURL, _ = sp.MakeRedirectAuthenticationRequest("")
	resp, _ = ob.do("GET", authURL.String(), nil, nil)
	if _, status := ob.signIn(resp.Header.Get("Location"), outsider.Email); status != http.StatusForbidden {
		t.Fatalf("outsider: %d", status)
	}

	// Disabled for a group: the flow stops before any response.
	if s := api.call("POST", "/apps/"+app.App.ID+"/rules", map[string]any{"name": "Group", "groups": []string{g.ID},
		"mode": "disabled"}, nil); s != http.StatusCreated {
		t.Fatalf("rule: %d", s)
	}
	resp, _ = b.do("GET", app.App.SAML.IdP.StartURL, nil, nil)
	resp, _ = b.do("GET", "/api/flow?authRequestID="+mustQuery(resp.Header.Get("Location"), "authRequestID"), nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disabled SAML app: %d", resp.StatusCode)
	}

	// SAML apps aren't OpenID Connect clients.
	q := url.Values{"client_id": {app.App.ID}, "redirect_uri": {sp.AcsURL.String()}, "response_type": {"code"},
		"scope": {"openid"}}
	if resp, _ := b.do("GET", "/authorize?"+q.Encode(), nil, nil); resp.StatusCode == http.StatusFound &&
		strings.Contains(resp.Header.Get("Location"), "/sign-in") {
		t.Fatal("SAML app accepted at /authorize")
	}

	// Delete.
	if s := api.call("DELETE", "/own-apps/"+app.App.ID, nil, nil); s != 204 {
		t.Fatalf("delete: %d", s)
	}
	if resp, _ := b.do("GET", app.App.SAML.IdP.MetadataURL, nil, nil); resp.StatusCode != 404 {
		t.Fatalf("deleted app's metadata: %d", resp.StatusCode)
	}
}

func mustQuery(raw, key string) string {
	u, _ := url.Parse(raw)
	return u.Query().Get(key)
}
