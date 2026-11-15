// Package auth checks Keston ID access tokens. Tokens are JWTs signed by
// Keston ID; an API checks them itself against Keston ID's published keys,
// so it doesn't call Keston ID for each request (and keeps working through a
// short Keston ID outage, until tokens expire: they live about 15 minutes).
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/thekestongroup/id/kit/apierr"
)

// KeySet gives the keys tokens may be signed with.
type KeySet interface {
	Keys(ctx context.Context) ([]jose.JSONWebKey, error)
}

// Verifier checks access tokens for one API.
type Verifier struct {
	Issuer   string
	Audience string
	Keys     KeySet
	// Leeway for clock differences between servers.
	Leeway time.Duration
	now    func() time.Time
}

// NewVerifier checks tokens from issuer (Keston ID's address) for audience
// (this API), signed with keys from keys (RemoteKeys(issuer) for a product).
func NewVerifier(issuer, audience string, keys KeySet) *Verifier {
	return &Verifier{Issuer: strings.TrimSuffix(issuer, "/"), Audience: audience, Keys: keys, Leeway: time.Minute,
		now: time.Now}
}

var (
	ErrMalformed = errors.New("token: malformed")
	ErrSignature = errors.New("token: bad signature")
	ErrIssuer    = errors.New("token: wrong issuer")
	ErrAudience  = errors.New("token: not for this API")
	ErrExpired   = errors.New("token: expired")
)

// Verify checks a token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil || len(tok.Headers) != 1 {
		return nil, ErrMalformed
	}
	keys, err := v.Keys.Keys(ctx)
	if err != nil {
		return nil, fmt.Errorf("token: keys: %w", err)
	}
	kid := tok.Headers[0].KeyID
	var claims Claims
	ok := false
	for _, k := range keys {
		if kid != "" && k.KeyID != kid {
			continue
		}
		if tok.Claims(k.Key, &claims) == nil {
			ok = true
			break
		}
	}
	if !ok {
		// A new key we haven't fetched yet: ask once more.
		if r, can := v.Keys.(interface{ Refresh(context.Context) error }); can && r.Refresh(ctx) == nil {
			keys, _ = v.Keys.Keys(ctx)
			for _, k := range keys {
				if k.KeyID == kid && tok.Claims(k.Key, &claims) == nil {
					ok = true
					break
				}
			}
		}
	}
	if !ok {
		return nil, ErrSignature
	}
	now := v.now()
	switch {
	case strings.TrimSuffix(claims.Issuer, "/") != v.Issuer:
		return nil, ErrIssuer
	case !slices.Contains(claims.Audience, v.Audience):
		return nil, ErrAudience
	case claims.Expiry == 0 || now.After(time.Unix(claims.Expiry, 0).Add(v.Leeway)):
		return nil, ErrExpired
	case claims.NotBefore != 0 && now.Add(v.Leeway).Before(time.Unix(claims.NotBefore, 0)):
		return nil, ErrExpired
	}
	return &claims, nil
}

// Middleware requires a valid "Authorization: Bearer …" token and puts the
// caller in the request context (FromContext).
func Middleware(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || raw == "" {
				apierr.Write(w, http.StatusUnauthorized, "signed_out", "Sign in to continue.")
				return
			}
			c, err := v.Verify(r.Context(), raw)
			if err != nil {
				apierr.Unauthorized(w)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), c)))
		})
	}
}

// Require lets a request through only with this permission in the caller's
// own organisation.
func Require(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := FromContext(r.Context())
			if c == nil {
				apierr.Unauthorized(w)
				return
			}
			if !c.Can(permission) {
				apierr.Forbidden(w, "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// audience is "aud", which JWTs allow as a string or a list.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}
