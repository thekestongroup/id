// Package oidcstore implements zitadel/oidc's op.Storage on top of Postgres.
// It keeps no state of its own beyond a short key cache, so any number of
// replicas can serve the same issuer.
package oidcstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
	"github.com/thekestongroup/id/kit/auth"
)

type Storage struct {
	store *store.Store
	cfg   *config.Config

	keysMu     sync.Mutex
	keys       []loadedKey
	keysLoaded time.Time
}

var _ op.Storage = (*Storage)(nil)
var _ op.CanSetUserinfoFromRequest = (*Storage)(nil)

func New(s *store.Store, cfg *config.Config) *Storage { return &Storage{store: s, cfg: cfg} }

func (s *Storage) Health(ctx context.Context) error { return s.store.DB.Ping(ctx) }

// ── Auth requests ────────────────────────────────────────────────────────

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	a := &store.AuthRequest{
		ClientID:     req.ClientID,
		RedirectURI:  req.RedirectURI,
		Scopes:       req.Scopes,
		State:        req.State,
		Nonce:        req.Nonce,
		ResponseType: string(req.ResponseType),
		ResponseMode: string(req.ResponseMode),
		LoginHint:    req.LoginHint,
		Prompt:       []string(req.Prompt),
	}
	if a.Prompt == nil {
		a.Prompt = []string{}
	}
	if req.CodeChallenge != "" {
		a.CodeChallenge = req.CodeChallenge
		a.CodeChallengeMethod = string(req.CodeChallengeMethod)
	}
	if req.MaxAge != nil {
		v := int32(*req.MaxAge)
		a.MaxAgeSeconds = &v
	}
	created, err := s.store.CreateAuthRequest(ctx, a, s.cfg.AuthRequestTTL)
	if err != nil {
		return nil, err
	}
	return authRequest{created, s.audience(ctx, created.ClientID)}, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	a, err := s.store.AuthRequestByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	return authRequest{a, s.audience(ctx, a.ClientID)}, nil
}

func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	a, err := s.store.AuthRequestByCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("auth code: %w", err)
	}
	return authRequest{a, s.audience(ctx, a.ClientID)}, nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return s.store.SaveAuthCode(ctx, id, code)
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.store.DeleteAuthRequest(ctx, id)
}

// ── Tokens ───────────────────────────────────────────────────────────────

// requestInfo pulls what every token needs out of the request types the
// library passes in (code flow or refresh).
func requestInfo(req op.TokenRequest) (clientID string, amr []string, authTime time.Time, sessionID *string) {
	switch r := req.(type) {
	case authRequest:
		return r.ClientID, r.AMR, r.GetAuthTime(), r.SessionID
	case *refreshRequest:
		return r.ClientID, r.AMR, r.AuthTime, r.SessionID
	}
	return "", nil, time.Time{}, nil
}

// canIssue: tokens are only issued to (and refreshed for) people who could
// sign in now: active, and in a verified organisation.
func (s *Storage) canIssue(ctx context.Context, userID string) error {
	u, err := s.store.UserByID(ctx, userID)
	if err != nil || !u.Usable() {
		return oidc.ErrAccessDenied().WithDescription("this account can't sign in")
	}
	return nil
}

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	clientID, _, _, sessionID := requestInfo(req)
	user := req.GetSubject()
	if err := s.canIssue(ctx, user); err != nil {
		return "", time.Time{}, err
	}
	return s.store.CreateAccessToken(ctx, s.store.DB, clientID, &user, req.GetAudience(), req.GetScopes(), nil,
		sessionID, s.cfg.AccessTokenTTL)
}

// CreateAccessAndRefreshTokens issues a new pair. With currentRefreshToken
// set (a refresh), the old refresh token is used up in the same transaction:
// rotation, so a stolen refresh token stops working once either party uses it.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest,
	currentRefreshToken string) (string, string, time.Time, error) {
	clientID, amr, authTime, sessionID := requestInfo(req)
	if err := s.canIssue(ctx, req.GetSubject()); err != nil {
		return "", "", time.Time{}, err
	}
	tx, err := s.store.DB.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	defer tx.Rollback(ctx)

	if currentRefreshToken != "" {
		if _, err := s.store.TakeRefreshToken(ctx, tx, currentRefreshToken); err != nil {
			return "", "", time.Time{}, op.ErrInvalidRefreshToken
		}
	}
	refresh, refreshID, err := s.store.CreateRefreshToken(ctx, tx, &store.RefreshToken{
		ClientID:  clientID,
		UserID:    req.GetSubject(),
		Audience:  req.GetAudience(),
		Scopes:    req.GetScopes(),
		AMR:       amr,
		AuthTime:  authTime,
		SessionID: sessionID,
	}, s.cfg.RefreshTokenTTL)
	if err != nil {
		return "", "", time.Time{}, err
	}
	user := req.GetSubject()
	accessID, exp, err := s.store.CreateAccessToken(ctx, tx, clientID, &user, req.GetAudience(), req.GetScopes(),
		&refreshID, sessionID, s.cfg.AccessTokenTTL)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, err
	}
	return accessID, refresh, exp, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, token string) (op.RefreshTokenRequest, error) {
	r, err := s.store.RefreshTokenByToken(ctx, token)
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if s.canIssue(ctx, r.UserID) != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	return &refreshRequest{RefreshToken: r, token: token}, nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	r, err := s.store.RefreshTokenByToken(ctx, token)
	if err != nil || r.ClientID != clientID {
		return "", "", op.ErrInvalidRefreshToken
	}
	return r.UserID, r.ID, nil
}

// TerminateSession ends an app's session (RP-initiated logout): its tokens
// for this person stop working. Its grant stays, so signing in again
// doesn't ask for consent again.
func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	for _, q := range []string{
		`DELETE FROM access_tokens WHERE user_id = $1 AND client_id = $2`,
		`DELETE FROM refresh_tokens WHERE user_id = $1 AND client_id = $2`,
	} {
		if _, err := s.store.DB.Exec(ctx, q, userID, clientID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeToken (RFC 7009). An unknown token still counts as revoked.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrID, _ string, clientID string) *oidc.Error {
	if cid, _, _, err := s.store.AccessTokenActive(ctx, tokenOrID); err == nil {
		if cid != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		if _, err := s.store.DeleteAccessToken(ctx, tokenOrID); err != nil {
			return oidc.ErrServerError()
		}
		return nil
	}
	if r, err := s.store.RefreshTokenByToken(ctx, tokenOrID); err == nil {
		if r.ClientID != clientID {
			return oidc.ErrInvalidClient().WithDescription("token was not issued to this client")
		}
		if err := s.store.DeleteRefreshTokenByID(ctx, r.ID); err != nil {
			return oidc.ErrServerError()
		}
	}
	return nil
}

// ── Clients ──────────────────────────────────────────────────────────────

func (s *Storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	c, err := s.store.ClientByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("client %q: %w", id, err)
	}
	if c.Protocol != "oidc" { // SAML apps sign in through /saml (internal/samlidp)
		return nil, fmt.Errorf("client %q: not an OpenID Connect app", id)
	}
	if c.RetiredAt != nil { // a Keston-wide app a TKG Admin retired
		return nil, fmt.Errorf("client %q: retired", id)
	}
	return client{Client: c, idTokenTTL: s.cfg.IDTokenTTL}, nil
}

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, id, clientSecret string) error {
	c, err := s.store.ClientByID(ctx, id)
	if err != nil || c.SecretHash == nil || c.Protocol != "oidc" || c.RetiredAt != nil {
		return errors.New("invalid client")
	}
	ok, err := secret.CheckPassword(*c.SecretHash, clientSecret)
	if err != nil || !ok {
		return errors.New("invalid client")
	}
	return nil
}

// ── Userinfo ─────────────────────────────────────────────────────────────

func (s *Storage) setUserinfo(ctx context.Context, info *oidc.UserInfo, userID string, scopes []string) error {
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.Status != "active" || !u.OrganisationVerified {
		return errors.New("account disabled")
	}
	info.Subject = u.ID
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.Name = u.Name
		info.PreferredUsername = u.Email
		info.UpdatedAt = oidc.FromTime(u.CreatedAt)
		info.Picture = profile.PictureURL(s.cfg.Issuer, u.ID, u.PictureUpdatedAt)
		if u.Organisation != "" {
			info.AppendClaims("organisation", u.Organisation)
		}
	}
	if slices.Contains(scopes, oidc.ScopeEmail) {
		info.Email = u.Email
		// Accounts are created by schools, with addresses they manage.
		info.EmailVerified = true
	}
	return nil
}

func (s *Storage) SetUserinfoFromScopes(ctx context.Context, info *oidc.UserInfo, userID, _ string,
	scopes []string) error {
	return s.setUserinfo(ctx, info, userID, scopes)
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, req op.IDTokenRequest,
	scopes []string) error {
	return s.setUserinfo(ctx, info, req.GetSubject(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	_, userID, scopes, err := s.store.AccessTokenActive(ctx, tokenID)
	if err != nil {
		return errors.New("token is not active")
	}
	if userID == nil || *userID != subject {
		return errors.New("token subject mismatch")
	}
	return s.setUserinfo(ctx, info, subject, scopes)
}

func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject,
	clientID string) error {
	cid, userID, scopes, err := s.store.AccessTokenActive(ctx, tokenID)
	if err != nil {
		return errors.New("token is not active")
	}
	// Only the app the token was issued to may introspect it.
	if cid != clientID {
		return errors.New("token was not issued to this client")
	}
	if userID == nil || *userID != subject {
		return errors.New("token subject mismatch")
	}
	info := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, info, subject, scopes); err != nil {
		return err
	}
	resp.SetUserInfo(info)
	resp.Scope = scopes
	resp.ClientID = cid
	return nil
}

// ── Who tokens are for, and what they say ───────────────────────────────

// audience: which APIs accept an app's access tokens. Each Keston API checks
// its own audience (kit/auth):
//   - Keston Admin: Keston ID's API and every Keston product's API, as it
//     manages them all
//   - Keston's own apps (e.g. Keston Work): their own API and Keston ID's
//   - other apps: only themselves (Keston ID's userinfo)
func (s *Storage) audience(ctx context.Context, clientID string) []string {
	aud := []string{clientID}
	c, err := s.store.ClientByID(ctx, clientID)
	if err != nil || !keston(c) {
		return aud
	}
	aud = append(aud, auth.AudienceKestonID)
	if clientID == adminClientID {
		products, err := s.store.BuiltinClients(ctx)
		if err == nil {
			for _, p := range products {
				aud = append(aud, p.ID)
			}
		}
	}
	return aud
}

// keston: one of Keston's own apps. An organisation's own apps never are,
// whatever else is set.
func keston(c *store.Client) bool { return c.Verification == "owned" && c.OrganisationID == nil }

// adminClientID is Keston Admin's client ID.
const adminClientID = "admin"

// GetPrivateClaimsFromScopes adds, for Keston's own apps, what Keston APIs
// need to authorise the caller without asking Keston ID (kit/auth.Claims):
// their organisation, their permissions there, and whether they're Keston
// staff. Third-party apps don't get these.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, _ []string) (map[string]any,
	error) {
	c, err := s.store.ClientByID(ctx, clientID)
	if err != nil || !keston(c) || userID == "" {
		return nil, nil
	}
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return nil, nil
	}
	perms, err := s.store.PermissionsOf(ctx, u)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"org":            u.OrganisationID,
		"perms":          perms.List(),
		"platform_admin": u.PlatformAdmin,
	}, nil
}

// JWT profile grants (service accounts) aren't supported yet.
func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("jwt profile not supported")
}

func (s *Storage) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// ── Signing keys ─────────────────────────────────────────────────────────

const (
	keyRotation   = 90 * 24 * time.Hour
	keyCacheTTL   = time.Minute
	retiredKeyTTL = 48 * time.Hour // longer than any ID or access token lives
)

type loadedKey struct {
	id      string
	key     *rsa.PrivateKey
	retired bool
	created time.Time
}

type signingKey struct{ loadedKey }

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Key() any                                    { return k.key }
func (k signingKey) ID() string                                  { return k.id }

type publicKey struct{ loadedKey }

func (k publicKey) ID() string                         { return k.id }
func (k publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k publicKey) Use() string                        { return "sig" }
func (k publicKey) Key() any                           { return &k.key.PublicKey }

// loadKeys reads keys from Postgres, cached for a minute. Every replica
// signs with the same key and publishes the same set.
func (s *Storage) loadKeys(ctx context.Context) ([]loadedKey, error) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if time.Since(s.keysLoaded) < keyCacheTTL && len(s.keys) > 0 {
		return s.keys, nil
	}
	rows, err := s.store.SigningKeys(ctx, retiredKeyTTL)
	if err != nil {
		return nil, err
	}
	keys := make([]loadedKey, 0, len(rows))
	for _, row := range rows {
		der, err := s.store.Box.Open(row.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decrypt signing key %s (is KESTON_ID_SECRET_KEY right?): %w", row.ID, err)
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key %s is not RSA", row.ID)
		}
		keys = append(keys, loadedKey{id: row.ID, key: rsaKey, retired: row.RetiredAt != nil, created: row.CreatedAt})
	}
	s.keys, s.keysLoaded = keys, time.Now()
	return keys, nil
}

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	keys, err := s.loadKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 || keys[0].retired {
		return nil, errors.New("no active signing key")
	}
	return signingKey{keys[0]}, nil
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	keys, err := s.loadKeys(ctx)
	if err != nil {
		return nil, err
	}
	set := make([]op.Key, len(keys))
	for i, k := range keys {
		set[i] = publicKey{k}
	}
	return set, nil
}

// EnsureSigningKey creates the first key, or a new one every 90 days. Run at
// startup under the migration lock's protection of a unique key id, so
// replicas starting together don't each make one.
func (s *Storage) EnsureSigningKey(ctx context.Context) error {
	rows, err := s.store.SigningKeys(ctx, retiredKeyTTL)
	if err != nil {
		return err
	}
	if len(rows) > 0 && rows[0].RetiredAt == nil && time.Since(rows[0].CreatedAt) < keyRotation {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	id := time.Now().UTC().Format("2006-01-02") + "-" + secret.Token()[:8]
	if err := s.store.RotateSigningKey(ctx, &store.SigningKey{ID: id, Algorithm: "RS256",
		PrivateKey: s.store.Box.Seal(der)}); err != nil {
		return err
	}
	s.keysMu.Lock()
	s.keysLoaded = time.Time{}
	s.keysMu.Unlock()
	return nil
}
