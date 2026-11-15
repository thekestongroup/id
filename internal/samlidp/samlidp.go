// Package samlidp makes Keston ID a SAML 2.0 identity provider for the SAML
// apps organisations add in Keston Admin.
//
// Each app has its own IdP entity ID and endpoints, so two organisations
// can add the same service (which often uses one entity ID for everyone):
//
//	/saml/{clientID}/metadata  the IdP metadata to give the app (also its entity ID)
//	/saml/{clientID}/sso       SP-initiated sign-in (HTTP-Redirect or HTTP-POST)
//	/saml/{clientID}/start     IdP-initiated sign-in (a link to the app)
//	/saml/callback?id=…        back from Keston ID's sign-in: posts the response to the app
//
// Sign-in goes through Keston ID's normal sign-in (password, MFA, account
// choice) and app access checks: the SAML request is kept as an auth request
// (response_type "saml") and replayed once someone has signed in.
package samlidp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// Bindings a waiting SAML sign-in arrived with (auth_requests.response_mode).
const (
	bindingRedirect = "redirect"
	bindingPost     = "post"
	bindingIdP      = "idp" // started by Keston ID: no request
)

type IdP struct {
	store *store.Store
	cfg   *config.Config
	// sessionID: the ID of the browser's active Keston ID session ("" if
	// none), so only the browser that signed in gets the response.
	sessionID func(r *http.Request) string

	mu       sync.Mutex
	cert     *x509.Certificate
	key      *rsa.PrivateKey
	loadedAt time.Time
}

func New(s *store.Store, cfg *config.Config, sessionID func(*http.Request) string) *IdP {
	return &IdP{store: s, cfg: cfg, sessionID: sessionID}
}

// Routes are mounted at /saml.
func (p *IdP) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/callback", p.callback)
	r.Get("/{clientID}/metadata", p.metadata)
	r.Get("/{clientID}/sso", p.sso)
	r.Post("/{clientID}/sso", p.sso)
	r.Get("/{clientID}/start", p.start)
	return r
}

// ── What to give the app ─────────────────────────────────────────────────

// AppInfo: the IdP details an admin gives a SAML app.
type AppInfo struct {
	EntityID    string `json:"entityId"`
	MetadataURL string `json:"metadataUrl"`
	SSOURL      string `json:"ssoUrl"`
	StartURL    string `json:"startUrl"`
	Certificate string `json:"certificate"` // PEM
	NameID      string `json:"nameIdFormat"`
	// The attributes sent, by name.
	Attributes []string `json:"attributes"`
}

func (p *IdP) base(clientID string) string {
	return p.cfg.Issuer + "/saml/" + url.PathEscape(clientID)
}

func (p *IdP) Info(ctx context.Context, clientID string) (AppInfo, error) {
	cert, _, err := p.keys(ctx)
	if err != nil {
		return AppInfo{}, err
	}
	base := p.base(clientID)
	return AppInfo{
		EntityID:    base + "/metadata",
		MetadataURL: base + "/metadata",
		SSOURL:      base + "/sso",
		StartURL:    base + "/start",
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		NameID:      string(saml.EmailAddressNameIDFormat),
		Attributes:  []string{attrEmail, attrName, attrGivenName, attrFamilyName, attrGroups},
	}, nil
}

// ── The identity provider for one app ────────────────────────────────────

func (p *IdP) provider(ctx context.Context, client *store.Client) (*saml.IdentityProvider, error) {
	cert, key, err := p.keys(ctx)
	if err != nil {
		return nil, err
	}
	base := p.base(client.ID)
	metadataURL, _ := url.Parse(base + "/metadata")
	ssoURL, _ := url.Parse(base + "/sso")
	return &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		Logger:                  slogLogger{},
		MetadataURL:             *metadataURL,
		SSOURL:                  *ssoURL,
		NameIDFormats:           []saml.NameIDFormat{saml.EmailAddressNameIDFormat},
		ServiceProviderProvider: serviceProviders{p.store, client.ID},
		SessionProvider:         waitForSignIn{p, client},
		SignatureMethod:         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		OnError: func(w http.ResponseWriter, r *http.Request, status int, err error) {
			slog.WarnContext(r.Context(), "saml", "app", client.ID, "error", err)
			fail(w, status, "This app's sign-in request didn't work. Go back to the app and try again, "+
				"or ask your organisation's admins to check its SAML settings in Keston Admin.")
		},
	}, nil
}

// app: the SAML app in the URL, or an error page.
func (p *IdP) app(w http.ResponseWriter, r *http.Request) *store.Client {
	c, err := p.store.ClientByID(r.Context(), chi.URLParam(r, "clientID"))
	if err != nil || c.Protocol != "saml" {
		fail(w, http.StatusNotFound, "This app isn't set up for SAML sign-in with Keston ID.")
		return nil
	}
	return c
}

func (p *IdP) metadata(w http.ResponseWriter, r *http.Request) {
	c := p.app(w, r)
	if c == nil {
		return
	}
	idp, err := p.provider(r.Context(), c)
	if err != nil {
		serverError(w, r, err)
		return
	}
	idp.ServeMetadata(w, r)
}

// sso: an app's sign-in request. Checked here (signature, destination, ACS
// URL), then kept until someone has signed in (waitForSignIn).
func (p *IdP) sso(w http.ResponseWriter, r *http.Request) {
	c := p.app(w, r)
	if c == nil {
		return
	}
	idp, err := p.provider(r.Context(), c)
	if err != nil {
		serverError(w, r, err)
		return
	}
	idp.ServeSSO(w, r)
}

// start: IdP-initiated sign-in, e.g. from a link to the app. RelayState is
// passed on to the app.
func (p *IdP) start(w http.ResponseWriter, r *http.Request) {
	c := p.app(w, r)
	if c == nil {
		return
	}
	app, err := p.store.SAMLApp(r.Context(), c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	relay := r.URL.Query().Get("RelayState")
	if len(relay) > 80 {
		fail(w, http.StatusBadRequest, "RelayState is too long.")
		return
	}
	ar, err := p.store.CreateSAMLAuthRequest(r.Context(), c.ID, bindingIdP, "", app.ACSURL, relay, false,
		p.cfg.AuthRequestTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/sign-in?authRequestID="+url.QueryEscape(ar.ID), http.StatusFound)
}

// waitForSignIn is the SessionProvider for requests arriving at /sso: it
// keeps the request as an auth request and sends people to Keston ID's
// sign-in, which comes back to /saml/callback.
type waitForSignIn struct {
	p      *IdP
	client *store.Client
}

func (s waitForSignIn) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	binding, raw := bindingRedirect, r.URL.RawQuery
	if r.Method == http.MethodPost {
		binding, raw = bindingPost, r.PostForm.Encode()
	}
	force := req.Request.ForceAuthn != nil && *req.Request.ForceAuthn
	ar, err := s.p.store.CreateSAMLAuthRequest(r.Context(), s.client.ID, binding, raw, req.ACSEndpoint.Location,
		req.RelayState, force, s.p.cfg.AuthRequestTTL)
	if err != nil {
		serverError(w, r, err)
		return nil
	}
	http.Redirect(w, r, "/sign-in?authRequestID="+url.QueryEscape(ar.ID), http.StatusFound)
	return nil
}

// serviceProviders: the one SAML app an IdP is for, by its entity ID.
type serviceProviders struct {
	store    *store.Store
	clientID string
}

func (sp serviceProviders) GetServiceProvider(r *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	app, err := sp.store.SAMLApp(r.Context(), sp.clientID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && app.EntityID != entityID) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	ed, _, err := ParseSPMetadata([]byte(app.Metadata))
	return ed, err
}

// ── Back from sign-in ────────────────────────────────────────────────────

func (p *IdP) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ar, err := p.store.AuthRequestByID(ctx, r.URL.Query().Get("id"))
	if err != nil || ar.ResponseType != "saml" || !ar.Done || ar.UserID == nil || ar.SessionID == nil {
		fail(w, http.StatusGone, "This sign-in link has expired. Go back to the app and try again.")
		return
	}
	// Only the browser that signed in.
	if p.sessionID(r) != *ar.SessionID {
		fail(w, http.StatusForbidden, "Sign in again to continue to the app.")
		return
	}
	c, err := p.store.ClientByID(ctx, ar.ClientID)
	if err != nil || c.Protocol != "saml" {
		fail(w, http.StatusGone, "This app is no longer set up with Keston ID.")
		return
	}
	user, err := p.store.UserByID(ctx, *ar.UserID)
	if err != nil || !user.Usable() || c.OrganisationID == nil || *c.OrganisationID != user.OrganisationID {
		fail(w, http.StatusForbidden, "Your account can't sign in to this app.")
		return
	}
	idp, err := p.provider(ctx, c)
	if err != nil {
		serverError(w, r, err)
		return
	}
	raw, err := p.store.SAMLRequest(ctx, ar.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// Used once.
	_ = p.store.DeleteAuthRequest(ctx, ar.ID)

	var req *saml.IdpAuthnRequest
	switch ar.ResponseMode {
	case bindingIdP:
		app, err := p.store.SAMLApp(ctx, c.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if req, err = idp.NewIdpInitiatedRequest(r, app.EntityID, ar.State); err != nil {
			idp.OnError(w, r, http.StatusBadRequest, err)
			return
		}
	default:
		// The request as it arrived, checked again as of when it arrived
		// (it was valid then; sign-in may have taken a while).
		orig := &http.Request{Method: http.MethodGet, URL: &url.URL{RawQuery: raw}, Header: http.Header{},
			RemoteAddr: r.RemoteAddr, Body: http.NoBody}
		if ar.ResponseMode == bindingPost {
			form, _ := url.ParseQuery(raw)
			orig.Method, orig.URL, orig.PostForm, orig.Form = http.MethodPost, &url.URL{}, form, form
		}
		orig = orig.WithContext(ctx)
		if req, err = saml.NewIdpAuthnRequest(idp, orig); err == nil {
			req.Now = ar.CreatedAt
			err = req.Validate()
		}
		if err != nil {
			idp.OnError(w, r, http.StatusBadRequest, err)
			return
		}
		req.HTTPRequest = r
	}
	req.Now = time.Now()

	session, err := p.session(ctx, ar, user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		idp.OnError(w, r, http.StatusInternalServerError, err)
		return
	}
	req.Assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: attributes(session)}}
	slog.InfoContext(ctx, "saml sign-in", "app", c.ID, "user", user.ID)
	if err := req.WriteResponse(w); err != nil {
		serverError(w, r, err)
	}
}

// ── Who signed in ────────────────────────────────────────────────────────

// Attribute names sent to apps, as in Keston ID's OpenID Connect claims.
const (
	attrEmail      = "email"
	attrName       = "name"
	attrGivenName  = "given_name"
	attrFamilyName = "family_name"
	attrGroups     = "groups"
)

func (p *IdP) session(ctx context.Context, ar *store.AuthRequest, u *store.User) (*saml.Session, error) {
	groups, err := p.store.GroupNamesForUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	given, family := splitName(u.Name)
	authTime := time.Now()
	if ar.AuthTime != nil {
		authTime = *ar.AuthTime
	}
	return &saml.Session{
		ID:             ar.ID,
		CreateTime:     authTime,
		Index:          secret.Hash(*ar.SessionID)[:32],
		NameID:         u.Email,
		NameIDFormat:   string(saml.EmailAddressNameIDFormat),
		UserEmail:      u.Email,
		UserCommonName: u.Name,
		UserGivenName:  given,
		UserSurname:    family,
		Groups:         groups,
	}, nil
}

func attributes(s *saml.Session) []saml.Attribute {
	attr := func(name string, values ...string) saml.Attribute {
		a := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}
		for _, v := range values {
			a.Values = append(a.Values, saml.AttributeValue{Type: "xs:string", Value: v})
		}
		return a
	}
	out := []saml.Attribute{attr(attrEmail, s.UserEmail), attr(attrName, s.UserCommonName)}
	if s.UserGivenName != "" {
		out = append(out, attr(attrGivenName, s.UserGivenName))
	}
	if s.UserSurname != "" {
		out = append(out, attr(attrFamilyName, s.UserSurname))
	}
	if len(s.Groups) > 0 {
		out = append(out, attr(attrGroups, s.Groups...))
	}
	return out
}

// splitName: accounts have one name; apps often want given and family
// names. The first word, and the rest.
func splitName(name string) (string, string) {
	given, family, _ := strings.Cut(strings.TrimSpace(name), " ")
	return given, strings.TrimSpace(family)
}

// ── Signing certificate ──────────────────────────────────────────────────

const certCacheTTL = time.Minute

func (p *IdP) keys(ctx context.Context) (*x509.Certificate, *rsa.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cert != nil && time.Since(p.loadedAt) < certCacheTTL {
		return p.cert, p.key, nil
	}
	row, err := p.store.SAMLCertificate(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("saml certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(row.Certificate)
	if err != nil {
		return nil, nil, err
	}
	der, err := p.store.Box.Open(row.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt saml key (is KESTON_ID_SECRET_KEY right?): %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("saml key is not RSA")
	}
	p.cert, p.key, p.loadedAt = cert, key, time.Now()
	return cert, key, nil
}

// EnsureCertificate makes the signing certificate if there isn't one: a
// self-signed RSA certificate, valid for 10 years (apps trust it because
// it's in the IdP metadata, not because of who issued it). Run at start,
// under a lock so replicas starting together make one.
func (p *IdP) EnsureCertificate(ctx context.Context) error {
	if _, err := p.store.SAMLCertificate(ctx); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	host := p.cfg.Issuer
	if u, err := url.Parse(p.cfg.Issuer); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Keston ID"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return p.store.AddSAMLCertificate(ctx, &store.SAMLCertificate{
		ID:          now.UTC().Format("2006-01-02") + "-" + secret.Token()[:8],
		Certificate: certDER,
		PrivateKey:  p.store.Box.Seal(keyDER),
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────

func fail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

func serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "saml error", "path", r.URL.Path, "error", err)
	fail(w, http.StatusInternalServerError, "Something went wrong. Try again.")
}

type slogLogger struct{}

func (slogLogger) Printf(format string, v ...any) {
	slog.Warn("saml", "message", fmt.Sprintf(format, v...))
}
func (slogLogger) Print(v ...any)   { slog.Warn("saml", "message", fmt.Sprint(v...)) }
func (slogLogger) Println(v ...any) { slog.Warn("saml", "message", fmt.Sprint(v...)) }
func (slogLogger) Fatal(v ...any)   { slog.Error("saml", "message", fmt.Sprint(v...)) }
func (slogLogger) Fatalf(format string, v ...any) {
	slog.Error("saml", "message", fmt.Sprintf(format, v...))
}
func (slogLogger) Fatalln(v ...any) { slog.Error("saml", "message", fmt.Sprint(v...)) }
func (slogLogger) Panic(v ...any)   { slog.Error("saml", "message", fmt.Sprint(v...)) }
func (slogLogger) Panicf(format string, v ...any) {
	slog.Error("saml", "message", fmt.Sprintf(format, v...))
}
func (slogLogger) Panicln(v ...any) { slog.Error("saml", "message", fmt.Sprint(v...)) }
