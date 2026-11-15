// Package principal is who's calling Keston ID's API (/v1), however they
// signed in: with an access token (Keston Admin, Keston's other apps, later
// third-party apps), or with Keston ID's own session cookie (the account
// pages on Keston ID's site). Every /v1 handler gets the same Caller, so
// each endpoint is written once for all of them.
package principal

import (
	"context"
	"net/http"
	"strings"

	"github.com/thekestongroup/id/internal/store"
	"github.com/thekestongroup/id/kit/apierr"
	"github.com/thekestongroup/id/kit/auth"
)

// Caller is the signed-in user.
type Caller struct {
	User *store.User
	// What they can do in Keston Admin, in their own organisation (current,
	// from the database rather than the token).
	Perms store.Perms
	// The Keston ID session they're signed in with; nil for a token issued
	// without one.
	Session *store.Session
	// The session cookie's token, for callers on Keston ID's own site
	// (empty for access tokens).
	SessionToken string
	// The access token's client (e.g. "admin"), empty for the cookie.
	ClientID string
}

// SessionID is their session's ID, or "".
func (c *Caller) SessionID() string {
	if c.Session == nil {
		return ""
	}
	return c.Session.ID
}

type ctxKey struct{}

func With(ctx context.Context, c *Caller) context.Context { return context.WithValue(ctx, ctxKey{}, c) }

// From is the caller (inside Middleware).
func From(ctx context.Context) *Caller {
	c, _ := ctx.Value(ctxKey{}).(*Caller)
	return c
}

// CookieSession finds the signed-in, fully verified browser session from
// Keston ID's cookie (the api package), or returns nils.
type CookieSession func(r *http.Request) (*store.Session, *store.User, string)

// Middleware requires a caller: a bearer access token for Keston ID's API
// (checked with kit/auth, then that it hasn't been revoked), or Keston ID's
// session cookie. Cookie requests that change something must carry the
// X-Keston-ID header, which other sites can't send (CSRF).
func Middleware(st *store.Store, verifier *auth.Verifier, cookie CookieSession) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			c := &Caller{}
			if header := r.Header.Get("Authorization"); header != "" {
				raw, ok := strings.CutPrefix(header, "Bearer ")
				if !ok || raw == "" {
					apierr.Unauthorized(w)
					return
				}
				claims, err := verifier.Verify(ctx, raw)
				if err != nil {
					apierr.Unauthorized(w)
					return
				}
				// Still live: not revoked by signing out, removing the app or
				// disabling the user.
				if _, userID, _, err := st.AccessTokenActive(ctx, claims.TokenID); err != nil || userID == nil ||
					*userID != claims.Subject {
					apierr.Unauthorized(w)
					return
				}
				user, err := st.UserByID(ctx, claims.Subject)
				if err != nil || !user.Usable() {
					apierr.Unauthorized(w)
					return
				}
				c.User, c.ClientID = user, claims.ClientID
				c.Session, _ = st.SessionForAccessToken(ctx, claims.TokenID)
			} else {
				if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Keston-ID") != "1" {
					apierr.Write(w, http.StatusForbidden, "forbidden", "Missing request header.")
					return
				}
				sess, user, token := cookie(r)
				if user == nil {
					apierr.Write(w, http.StatusUnauthorized, "signed_out", "Sign in to continue.")
					return
				}
				c.User, c.Session, c.SessionToken = user, sess, token
			}
			perms, err := st.PermissionsOf(ctx, c.User)
			if err != nil {
				apierr.Server(w, r, err)
				return
			}
			c.Perms = perms
			next.ServeHTTP(w, r.WithContext(With(ctx, c)))
		})
	}
}
