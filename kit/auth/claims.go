package auth

import (
	"context"
	"slices"
	"time"
)

// Audiences: who a token is for. Each Keston API accepts tokens whose
// audience includes its own. Keston ID's API is AudienceKestonID; a
// product's API uses its app's client ID (e.g. "work").
const AudienceKestonID = "keston-id"

// Claims is the caller, from their access token.
type Claims struct {
	// The user's ID.
	Subject string `json:"sub"`
	// The app the token was issued to (e.g. "admin" for Keston Admin).
	ClientID     string   `json:"client_id"`
	Audience     audience `json:"aud"`
	Issuer       string   `json:"iss"`
	TokenID      string   `json:"jti"`
	Expiry       int64    `json:"exp"`
	NotBefore    int64    `json:"nbf"`
	Scope        string   `json:"scope"`
	Organisation string   `json:"org"`
	// What they can do in their organisation, across Keston (only in tokens
	// for Keston's own apps).
	Permissions []string `json:"perms"`
	// Keston staff (The Keston Group's admins).
	PlatformAdmin bool `json:"platform_admin"`
}

// Can: they have this permission in their own organisation.
func (c *Claims) Can(permission string) bool { return slices.Contains(c.Permissions, permission) }

// CanIn: they have this permission in this organisation.
func (c *Claims) CanIn(orgID, permission string) bool {
	return c.Organisation == orgID && c.Can(permission)
}

// ExpiresAt is when the token stops working.
func (c *Claims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0) }

type ctxKey struct{}

// WithClaims puts the caller in a context (Middleware does this).
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext is the caller, or nil outside Middleware.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}
