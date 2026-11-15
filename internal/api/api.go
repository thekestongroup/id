// Package api is the JSON API behind the Keston ID web UI: signing in, the
// MFA code, consent, and account settings. The OAuth/OIDC endpoints
// themselves are zitadel/oidc's.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/store"
)

type API struct {
	store *store.Store
	cfg   *config.Config
	// endSession signs a Keston ID session out of its apps (revokes their
	// tokens, back-channel logout): oidcstore.Storage.EndSession.
	endSession func(ctx context.Context, sessionID string) error
}

func New(s *store.Store, cfg *config.Config, endSession func(context.Context, string) error) *API {
	return &API{store: s, cfg: cfg, endSession: endSession}
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
	r.Post("/consent", a.consent)
	r.Post("/sign-out", a.signOut)
	r.Get("/accounts", a.accounts)
	r.Post("/accounts/switch", a.switchAccount)

	r.Group(func(r chi.Router) {
		r.Use(a.requireVerified)
		r.Get("/me", a.me)
		r.Get("/me/apps", a.apps)
		r.Delete("/me/apps/{clientID}", a.revokeApp)
		r.Get("/me/sessions", a.sessions)
		r.Delete("/me/sessions/{sessionID}", a.signOutDevice)
		r.Patch("/me", a.updateProfile)
		r.Put("/me/picture", a.setPicture)
		r.Delete("/me/picture", a.removePicture)
		r.Post("/me/password", a.changePassword)
		r.Post("/me/mfa/setup", a.mfaSetup)
		r.Post("/me/mfa/enable", a.mfaEnable)
		r.Post("/me/mfa/disable", a.mfaDisable)
	})
	return r
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

type ctxKey struct{}

type current struct {
	session *store.Session
	user    *store.User
	token   string
}

func (a *API) requireVerified(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := a.current(r)
		if cur != nil {
			// An admin may have required something since (required.go).
			if _, err := a.settle(r.Context(), cur); err != nil {
				serverError(w, r, err)
				return
			}
		}
		if cur == nil || cur.session.Stage != "verified" {
			writeError(w, http.StatusUnauthorized, "signed_out", "Sign in to continue.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, cur)))
	})
}

func from(r *http.Request) *current { return r.Context().Value(ctxKey{}).(*current) }

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

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
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
