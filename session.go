package main

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

// Session implements both openid.Session and oauth2.JWTSessionContainer so it
// can back OpenID Connect ID tokens and stateless JWT access tokens.
type Session struct {
	*oauth2.JWTSession
	IDClaims  *jwt.IDTokenClaims
	IDHeaders *jwt.Headers
}

func newSession(user, audience string) *Session {
	extra := map[string]interface{}{
		"name":  "Administrator",
		"email": "admin@keston.local",
	}
	return &Session{
		JWTSession: &oauth2.JWTSession{
			JWTClaims: &jwt.JWTClaims{
				Subject: user,
				Extra:   extra,
			},
			JWTHeader: &jwt.Headers{Extra: map[string]interface{}{}},
			Subject:   user,
		},
		IDClaims: &jwt.IDTokenClaims{
			Issuer:      cfg.Issuer,
			Subject:     user,
			Audience:    []string{audience},
			ExpiresAt:   time.Now().Add(time.Hour),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra:       extra,
		},
		IDHeaders: &jwt.Headers{Extra: map[string]interface{}{}},
	}
}

func newEmptySession() *Session {
	return &Session{
		JWTSession: &oauth2.JWTSession{},
		IDClaims:   &jwt.IDTokenClaims{},
		IDHeaders:  &jwt.Headers{},
	}
}

func (s *Session) IDTokenClaims() *jwt.IDTokenClaims { return s.IDClaims }
func (s *Session) IDTokenHeaders() *jwt.Headers       { return s.IDHeaders }

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	return &Session{
		JWTSession: s.JWTSession.Clone().(*oauth2.JWTSession),
		IDClaims:   cloneIDTokenClaims(s.IDClaims),
		IDHeaders:  cloneHeaders(s.IDHeaders),
	}
}

func cloneIDTokenClaims(c *jwt.IDTokenClaims) *jwt.IDTokenClaims {
	if c == nil {
		return nil
	}
	out := *c
	out.Audience = append([]string{}, c.Audience...)
	out.AuthenticationMethodsReferences = append([]string{}, c.AuthenticationMethodsReferences...)
	out.Extra = cloneMap(c.Extra)
	return &out
}

func cloneHeaders(h *jwt.Headers) *jwt.Headers {
	if h == nil {
		return nil
	}
	out := *h
	out.Extra = cloneMap(h.Extra)
	return &out
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
