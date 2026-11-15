package oidcstore

import (
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/thekestongroup/id/internal/store"
)

// authRequest adapts a stored auth request to op.AuthRequest. audience is
// who its tokens are for (see Storage.audience).
type authRequest struct {
	*store.AuthRequest
	audience []string
}

var _ op.AuthRequest = authRequest{}

func (a authRequest) GetID() string    { return a.ID }
func (a authRequest) GetACR() string   { return "" }
func (a authRequest) GetAMR() []string { return a.AMR }
func (a authRequest) GetAudience() []string {
	if len(a.audience) == 0 {
		return []string{a.ClientID}
	}
	return a.audience
}
func (a authRequest) GetClientID() string                { return a.ClientID }
func (a authRequest) GetNonce() string                   { return a.Nonce }
func (a authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a authRequest) GetScopes() []string                { return a.Scopes }
func (a authRequest) GetState() string                   { return a.State }
func (a authRequest) Done() bool                         { return a.AuthRequest.Done }
func (a authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.ResponseType) }
func (a authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(a.ResponseMode) }

func (a authRequest) GetAuthTime() time.Time {
	if a.AuthTime == nil {
		return time.Time{}
	}
	return *a.AuthTime
}

func (a authRequest) GetSubject() string {
	if a.UserID == nil {
		return ""
	}
	return *a.UserID
}

func (a authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	method := oidc.CodeChallengeMethodPlain
	if a.CodeChallengeMethod == string(oidc.CodeChallengeMethodS256) {
		method = oidc.CodeChallengeMethodS256
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge, Method: method}
}

// refreshRequest adapts a stored refresh token to op.RefreshTokenRequest.
type refreshRequest struct {
	*store.RefreshToken
	token string
}

var _ op.RefreshTokenRequest = (*refreshRequest)(nil)

func (r *refreshRequest) GetAMR() []string                 { return r.AMR }
func (r *refreshRequest) GetAudience() []string            { return r.Audience }
func (r *refreshRequest) GetAuthTime() time.Time           { return r.AuthTime }
func (r *refreshRequest) GetClientID() string              { return r.ClientID }
func (r *refreshRequest) GetScopes() []string              { return r.Scopes }
func (r *refreshRequest) GetSubject() string               { return r.UserID }
func (r *refreshRequest) SetCurrentScopes(scopes []string) { r.Scopes = scopes }

// client adapts a registered app to op.Client.
type client struct {
	*store.Client
	idTokenTTL time.Duration
}

var _ op.Client = client{}

func (c client) GetID() string                    { return c.ID }
func (c client) RedirectURIs() []string           { return c.Client.RedirectURIs }
func (c client) PostLogoutRedirectURIs() []string { return c.Client.PostLogoutRedirectURIs }
func (c client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

// LoginURL is where /authorize sends people to sign in: the web UI.
func (c client) LoginURL(id string) string           { return "/sign-in?authRequestID=" + id }
func (c client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c client) IDTokenLifetime() time.Duration      { return c.idTokenTTL }
func (c client) DevMode() bool                       { return c.Client.DevMode }
func (c client) ClockSkew() time.Duration            { return 0 }

// Put profile and email claims in the ID token too, so apps don't need a
// userinfo call to show who's signed in.
func (c client) IDTokenUserinfoClaimsAssertion() bool { return true }

func (c client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

func (c client) IsScopeAllowed(scope string) bool {
	return slices.Contains(c.RequiredScopes, scope) || slices.Contains(c.OptionalScopes, scope)
}

func (c client) public() bool { return c.SecretHash == nil }

func (c client) ApplicationType() op.ApplicationType {
	// An organisation's single-page or mobile app: https, loopback and
	// custom-scheme (app) redirect URIs.
	if c.Native {
		return op.ApplicationTypeNative
	}
	if c.public() {
		return op.ApplicationTypeUserAgent
	}
	return op.ApplicationTypeWeb
}

func (c client) AuthMethod() oidc.AuthMethod {
	if c.public() {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}
