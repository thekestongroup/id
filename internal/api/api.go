// Package api is the JSON API behind the Keston ID web UI: signing in, the
// MFA code, consent, and account settings. The OAuth/OIDC endpoints
// themselves are zitadel/oidc's.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/thekestongroup/id/internal/clientip"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/principal"
	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/store"
)

type API struct {
	store *store.Store
	cfg   *config.Config
	// endSession signs a Keston ID session out of its apps (revokes their
	// tokens, back-channel logout): oidcstore.Storage.EndSession.
	endSession func(ctx context.Context, sessionID string) error
	// Passkeys and security keys (passkeys.go).
	webauthn *webauthn.WebAuthn
}

func New(s *store.Store, cfg *config.Config, endSession func(context.Context, string) error) *API {
	wa, err := newWebAuthn(cfg.Issuer)
	if err != nil {
		panic("webauthn: " + err.Error())
	}
	return &API{store: s, cfg: cfg, endSession: endSession, webauthn: wa}
}

func (a *API) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore, csrf)

	r.Get("/flow", a.flow)
	r.Post("/sign-in", a.signIn)
	r.Post("/mfa", a.mfa)
	r.Post("/sign-in/access-pass", a.signInWithPass)
	r.Post("/required/password", a.requiredPassword)
	r.Post("/required/mfa/setup", a.requiredMFASetup)
	r.Post("/required/mfa/enable", a.requiredMFAEnable)
	r.Post("/required/mfa/skip", a.requiredMFASkip)
	r.Post("/consent", a.consent)
	r.Post("/sign-out", a.signOut)
	r.Get("/accounts", a.accounts)
	r.Post("/accounts/switch", a.switchAccount)
	a.passkeyRoutes(r)

	return r
}

// MeRoutes is your own account, in Keston ID's API at /v1/me: the same
// endpoints for the account pages (session cookie) and apps (access
// tokens). The caller comes from principal.Middleware.
func (a *API) MeRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	r.Get("/", a.me)
	r.Patch("/", a.updateProfile)
	r.Get("/apps", a.apps)
	r.Delete("/apps/{clientID}", a.revokeApp)
	a.appRequestRoutes(r)
	r.Get("/sessions", a.sessions)
	r.Delete("/sessions/{sessionID}", a.signOutDevice)
	r.Put("/picture", a.setPicture)
	r.Delete("/picture", a.removePicture)
	r.Post("/password", a.changePassword)
	r.Post("/mfa/setup", a.mfaSetup)
	r.Post("/mfa/enable", a.mfaEnable)
	r.Post("/mfa/disable", a.mfaDisable)
	a.passkeyAccountRoutes(r)
	return r
}

// CookieSession is the browser's active, fully signed-in account, for
// principal.Middleware (Keston ID's own pages calling /v1).
func (a *API) CookieSession(r *http.Request) (*store.Session, *store.User, string) {
	cur := a.current(r)
	if cur == nil {
		return nil, nil, ""
	}
	// An admin may have required something since (required.go): then it's
	// not fully signed in any more.
	if _, err := a.settle(r.Context(), cur, store.SignInContext{IP: clientip.From(r)}); err != nil || cur.session.Stage != store.StageVerified {
		return nil, nil, ""
	}
	return cur.session, cur.user, cur.token
}

// ── Middleware ───────────────────────────────────────────────────────────

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// csrf: changes must carry a header the web UI adds. Other sites can't send
// custom headers without a CORS preflight, which Keston ID never allows.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-Keston-ID") != "1" {
			writeError(w, http.StatusForbidden, "forbidden", "Missing request header.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type current struct {
	session *store.Session
	user    *store.User
	token   string
}

// from: the caller of a /v1/me endpoint (principal.Middleware). session is
// nil for an access token issued without one; token is the session cookie's,
// empty for access tokens.
func from(r *http.Request) *current {
	c := principal.From(r.Context())
	return &current{session: c.Session, user: c.User, token: c.SessionToken}
}

// sessionID is the caller's Keston ID session, or "".
func (c *current) sessionID() string {
	if c.session == nil {
		return ""
	}
	return c.session.ID
}

// ── Helpers ──────────────────────────────────────────────────────────────

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

func writeFieldError(w http.ResponseWriter, field, message string) {
	writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: "invalid", Message: message, Field: field})
}

func serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "api error", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "server_error", "Something went wrong. Try again.")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return false
	}
	return true
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

// ── Shapes sent to the web UI ────────────────────────────────────────────

type clientView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Publisher    string `json:"publisher"`
	Verification string `json:"verification"`
	PrivacyURL   string `json:"privacyUrl"`
	TermsURL     string `json:"termsUrl"`
	RedirectHost string `json:"redirectHost,omitempty"`
}

func viewClient(c *store.Client, redirectURI string) clientView {
	v := clientView{ID: c.ID, Name: c.Name, Publisher: c.Publisher, Verification: c.Verification,
		PrivacyURL: c.PrivacyURL, TermsURL: c.TermsURL}
	if u, err := url.Parse(redirectURI); err == nil {
		v.RedirectHost = u.Host
	}
	return v
}

type userView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Organisation string `json:"organisation"`
	// Profile picture URL ("" for initials). Called avatar, as Keston UI's
	// Avatar expects.
	Avatar string `json:"avatar,omitempty"`
}

func (a *API) viewUser(u *store.User) userView {
	return userView{ID: u.ID, Name: u.Name, Email: u.Email, Organisation: u.Organisation,
		Avatar: profile.PictureURL(a.cfg.Issuer, u.ID, u.PictureUpdatedAt)}
}

func intersect(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// decodeOptional reads a JSON body if there is one.
func decodeOptional(r *http.Request, v any) error {
	if r.ContentLength == 0 {
		return nil
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	return json.NewDecoder(r.Body).Decode(v)
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
