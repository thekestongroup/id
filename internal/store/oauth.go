package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thekestongroup/id/internal/secret"
)

// ── Clients ──────────────────────────────────────────────────────────────

type Client struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Publisher              string   `json:"publisher"`
	Verification           string   `json:"verification"`
	SecretHash             *string  `json:"-"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	RequiredScopes         []string `json:"requiredScopes"`
	OptionalScopes         []string `json:"optionalScopes"`
	SkipConsent            bool     `json:"skipConsent"`
	BackchannelLogoutURI   string   `json:"backchannelLogoutUri"`
	PrivacyURL             string   `json:"privacyUrl"`
	TermsURL               string   `json:"termsUrl"`
	DevMode                bool     `json:"devMode"`
	// One of Keston's own apps, which every organisation has.
	Builtin bool `json:"builtin"`
	// The organisation that added it in Keston Admin (nil: registered by
	// Keston). Only its users can sign in to it.
	OrganisationID *string `json:"organisationId"`
	// "oidc" or "saml".
	Protocol string `json:"protocol"`
	LogoURL  string `json:"logoUrl"`
	// A single-page or mobile app (PKCE, no secret), added by an organisation.
	Native bool `json:"native"`
}

const clientColumns = `id, name, publisher, verification, secret_hash, redirect_uris, post_logout_redirect_uris,
	required_scopes, optional_scopes, skip_consent, backchannel_logout_uri, privacy_url, terms_url, dev_mode, builtin,
	organisation_id, protocol, logo_url, native`

func scanClient(row pgx.Row) (*Client, error) {
	var c Client
	if err := row.Scan(&c.ID, &c.Name, &c.Publisher, &c.Verification, &c.SecretHash, &c.RedirectURIs,
		&c.PostLogoutRedirectURIs, &c.RequiredScopes, &c.OptionalScopes, &c.SkipConsent, &c.BackchannelLogoutURI,
		&c.PrivacyURL, &c.TermsURL, &c.DevMode, &c.Builtin, &c.OrganisationID, &c.Protocol, &c.LogoURL,
		&c.Native); err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

func (s *Store) ClientByID(ctx context.Context, id string) (*Client, error) {
	return scanClient(s.DB.QueryRow(ctx, `SELECT `+clientColumns+` FROM clients WHERE id = $1`, id))
}

// UpsertClient registers or updates an app. A nil secretHash keeps the
// current secret; an empty one makes it a public client.
func (s *Store) UpsertClient(ctx context.Context, c *Client, secretHash *string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, verification, secret_hash, redirect_uris,
			post_logout_redirect_uris, required_scopes, optional_scopes, skip_consent, backchannel_logout_uri,
			privacy_url, terms_url, dev_mode, builtin)
		VALUES ($1, $2, $3, $4, nullif($5, ''), $6, $7, $8, $9, $10, $11, $12, $13, $14, $16)
		ON CONFLICT (id) DO UPDATE SET name = $2, publisher = $3, verification = $4,
			secret_hash = CASE WHEN $15 THEN nullif($5, '') ELSE clients.secret_hash END,
			redirect_uris = $6, post_logout_redirect_uris = $7, required_scopes = $8, optional_scopes = $9,
			skip_consent = $10, backchannel_logout_uri = $11, privacy_url = $12, terms_url = $13, dev_mode = $14,
			builtin = $16`,
		c.ID, c.Name, c.Publisher, c.Verification, deref(secretHash), c.RedirectURIs, c.PostLogoutRedirectURIs,
		c.RequiredScopes, c.OptionalScopes, c.SkipConsent, c.BackchannelLogoutURI, c.PrivacyURL, c.TermsURL,
		c.DevMode, secretHash != nil, c.Builtin)
	return err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ── Auth requests ────────────────────────────────────────────────────────

type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	MaxAgeSeconds       *int32
	LoginHint           string
	UserID              *string
	SessionID           *string
	AuthTime            *time.Time
	AMR                 []string
	Done                bool
	CreatedAt           time.Time
	AccountChosen       bool
}

const authRequestColumns = `id, client_id, redirect_uri, scopes, state, nonce, response_type, response_mode,
	code_challenge, code_challenge_method, prompt, max_age_seconds, login_hint, user_id, session_id, auth_time, amr,
	done, created_at, account_chosen`

func scanAuthRequest(row pgx.Row) (*AuthRequest, error) {
	var a AuthRequest
	if err := row.Scan(&a.ID, &a.ClientID, &a.RedirectURI, &a.Scopes, &a.State, &a.Nonce, &a.ResponseType,
		&a.ResponseMode, &a.CodeChallenge, &a.CodeChallengeMethod, &a.Prompt, &a.MaxAgeSeconds, &a.LoginHint,
		&a.UserID, &a.SessionID, &a.AuthTime, &a.AMR, &a.Done, &a.CreatedAt, &a.AccountChosen); err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) CreateAuthRequest(ctx context.Context, a *AuthRequest, ttl time.Duration) (*AuthRequest, error) {
	return scanAuthRequest(s.DB.QueryRow(ctx, `INSERT INTO auth_requests (client_id, redirect_uri, scopes, state,
			nonce, response_type, response_mode, code_challenge, code_challenge_method, prompt, max_age_seconds,
			login_hint, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() + $13::interval)
		RETURNING `+authRequestColumns,
		a.ClientID, a.RedirectURI, a.Scopes, a.State, a.Nonce, a.ResponseType, a.ResponseMode, a.CodeChallenge,
		a.CodeChallengeMethod, a.Prompt, a.MaxAgeSeconds, a.LoginHint, ttl))
}

func (s *Store) AuthRequestByID(ctx context.Context, id string) (*AuthRequest, error) {
	return scanAuthRequest(s.DB.QueryRow(ctx, `SELECT `+authRequestColumns+` FROM auth_requests
		WHERE id = $1 AND expires_at > now()`, id))
}

func (s *Store) AuthRequestByCode(ctx context.Context, code string) (*AuthRequest, error) {
	return scanAuthRequest(s.DB.QueryRow(ctx, `SELECT `+authRequestColumns+` FROM auth_requests
		WHERE code_hash = $1 AND expires_at > now()`, secret.Hash(code)))
}

func (s *Store) SaveAuthCode(ctx context.Context, id, code string) error {
	// A code is only good for 10 minutes.
	_, err := s.DB.Exec(ctx, `UPDATE auth_requests SET code_hash = $2,
		expires_at = least(expires_at, now() + interval '10 minutes') WHERE id = $1`, id, secret.Hash(code))
	return err
}

// CompleteAuthRequest records who signed in and what they allowed.
func (s *Store) CompleteAuthRequest(ctx context.Context, id string, sess *Session, scopes []string) error {
	_, err := s.DB.Exec(ctx, `UPDATE auth_requests SET user_id = $2, session_id = $3, auth_time = $4, amr = $5,
		scopes = $6, done = TRUE WHERE id = $1`, id, sess.UserID, sess.ID, sess.AuthTime, sess.AMR, scopes)
	return err
}

// ChooseAccount records that someone picked which account an app's sign-in
// uses, so the account chooser isn't shown again for it.
func (s *Store) ChooseAccount(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE auth_requests SET account_chosen = TRUE WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM auth_requests WHERE id = $1`, id)
	return err
}

// ── Grants ───────────────────────────────────────────────────────────────

type Grant struct {
	ClientID  string    `json:"clientId"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"grantedAt"`
}

func (s *Store) Grant(ctx context.Context, userID, clientID string) (*Grant, error) {
	var g Grant
	err := s.DB.QueryRow(ctx, `SELECT client_id, scopes, granted_at FROM grants WHERE user_id = $1 AND client_id = $2`,
		userID, clientID).Scan(&g.ClientID, &g.Scopes, &g.GrantedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

func (s *Store) SaveGrant(ctx context.Context, userID, clientID string, scopes []string) error {
	if _, err := s.DB.Exec(ctx, `DELETE FROM removed_apps WHERE user_id = $1 AND client_id = $2`, userID,
		clientID); err != nil {
		return err
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO grants (user_id, client_id, scopes) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $3, granted_at = now()`, userID, clientID, scopes)
	return err
}

func (s *Store) GrantsForUser(ctx context.Context, userID string) ([]Grant, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id, scopes, granted_at FROM grants WHERE user_id = $1
		ORDER BY granted_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Grant])
}

// RevokeClient removes an app's access: its grant and every token it holds.
func (s *Store) RevokeClient(ctx context.Context, userID, clientID string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{
		`DELETE FROM grants WHERE user_id = $1 AND client_id = $2`,
		`DELETE FROM access_tokens WHERE user_id = $1 AND client_id = $2`,
		`DELETE FROM refresh_tokens WHERE user_id = $1 AND client_id = $2`,
	} {
		if _, err := tx.Exec(ctx, q, userID, clientID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ── Tokens ───────────────────────────────────────────────────────────────

type RefreshToken struct {
	ID        string
	ClientID  string
	UserID    string
	Audience  []string
	Scopes    []string
	AMR       []string
	AuthTime  time.Time
	ExpiresAt time.Time
	// The Keston ID browser session it came from (nil: none, e.g. older tokens).
	SessionID *string
}

func (s *Store) CreateAccessToken(ctx context.Context, q Querier, clientID string, userID *string, audience,
	scopes []string, refreshTokenID, sessionID *string, ttl time.Duration) (string, time.Time, error) {
	var id string
	var exp time.Time
	err := q.QueryRow(ctx, `INSERT INTO access_tokens (client_id, user_id, audience, scopes, refresh_token_id, session_id,
			expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval) RETURNING id, expires_at`,
		clientID, userID, audience, scopes, refreshTokenID, sessionID, ttl).Scan(&id, &exp)
	return id, exp, err
}

// AccessTokenActive: the token exists (not revoked) and hasn't expired.
func (s *Store) AccessTokenActive(ctx context.Context, id string) (clientID string, userID *string, scopes []string,
	err error) {
	err = s.DB.QueryRow(ctx, `SELECT client_id, user_id, scopes FROM access_tokens WHERE id = $1 AND expires_at > now()`,
		id).Scan(&clientID, &userID, &scopes)
	return clientID, userID, scopes, notFound(err)
}

func (s *Store) DeleteAccessToken(ctx context.Context, id string) (int64, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM access_tokens WHERE id = $1`, id)
	return tag.RowsAffected(), err
}

// CreateRefreshToken returns the token itself; only its hash is stored.
func (s *Store) CreateRefreshToken(ctx context.Context, q Querier, r *RefreshToken, ttl time.Duration) (string, string,
	error) {
	token := secret.Token()
	var id string
	err := q.QueryRow(ctx, `INSERT INTO refresh_tokens (token_hash, client_id, user_id, audience, scopes, amr,
			auth_time, session_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + $9::interval) RETURNING id`,
		secret.Hash(token), r.ClientID, r.UserID, r.Audience, r.Scopes, r.AMR, r.AuthTime, r.SessionID, ttl).Scan(&id)
	return token, id, err
}

const refreshColumns = `id, client_id, user_id, audience, scopes, amr, auth_time, expires_at, session_id`

func scanRefresh(row pgx.Row) (*RefreshToken, error) {
	var r RefreshToken
	if err := row.Scan(&r.ID, &r.ClientID, &r.UserID, &r.Audience, &r.Scopes, &r.AMR, &r.AuthTime,
		&r.ExpiresAt, &r.SessionID); err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

func (s *Store) RefreshTokenByToken(ctx context.Context, token string) (*RefreshToken, error) {
	return scanRefresh(s.DB.QueryRow(ctx, `SELECT `+refreshColumns+` FROM refresh_tokens
		WHERE token_hash = $1 AND expires_at > now()`, secret.Hash(token)))
}

// TakeRefreshToken deletes a refresh token (and its access tokens) as it's
// used, inside tx: rotation means each refresh token works exactly once.
func (s *Store) TakeRefreshToken(ctx context.Context, tx pgx.Tx, token string) (*RefreshToken, error) {
	return scanRefresh(tx.QueryRow(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1 AND expires_at > now()
		RETURNING `+refreshColumns, secret.Hash(token)))
}

func (s *Store) DeleteRefreshTokenByID(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM refresh_tokens WHERE id = $1`, id)
	return err
}

// ── Signing keys ─────────────────────────────────────────────────────────

type SigningKey struct {
	ID         string
	Algorithm  string
	PrivateKey []byte // encrypted PKCS#8
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

// SigningKeys returns keys still published: the active one first, then
// retired ones that tokens may still be signed with.
func (s *Store) SigningKeys(ctx context.Context, keepRetiredFor time.Duration) ([]SigningKey, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, algorithm, private_key, created_at, retired_at FROM signing_keys
		WHERE retired_at IS NULL OR retired_at > now() - $1::interval
		ORDER BY retired_at IS NOT NULL, created_at DESC`, keepRetiredFor)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SigningKey])
}

// RotateSigningKey adds a new active key and retires the old one.
func (s *Store) RotateSigningKey(ctx context.Context, k *SigningKey) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE signing_keys SET retired_at = now() WHERE retired_at IS NULL`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO signing_keys (id, algorithm, private_key) VALUES ($1, $2, $3)`,
		k.ID, k.Algorithm, k.PrivateKey); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Querier is a pool or a transaction.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// SessionApp is an app signed in through a Keston ID session.
type SessionApp struct {
	ClientID             string
	UserID               string
	BackchannelLogoutURI string
}

// EndSessionApps revokes every app token that came from a Keston ID session,
// returning the apps that had them (to tell them, by back-channel logout).
func (s *Store) EndSessionApps(ctx context.Context, sessionID string) ([]SessionApp, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT DISTINCT t.client_id, t.user_id::text, c.backchannel_logout_uri
		FROM (SELECT client_id, user_id FROM access_tokens WHERE session_id = $1
		      UNION SELECT client_id, user_id FROM refresh_tokens WHERE session_id = $1) t
		JOIN clients c ON c.id = t.client_id`, sessionID)
	if err != nil {
		return nil, err
	}
	apps, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SessionApp])
	if err != nil {
		return nil, err
	}
	for _, q := range []string{
		`DELETE FROM access_tokens WHERE session_id = $1`,
		`DELETE FROM refresh_tokens WHERE session_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, sessionID); err != nil {
			return nil, err
		}
	}
	return apps, tx.Commit(ctx)
}

// SessionForAccessToken is the Keston ID session an access token was issued
// under, if it has one and it's still live.
func (s *Store) SessionForAccessToken(ctx context.Context, tokenID string) (*Session, error) {
	return scanSession(s.DB.QueryRow(ctx, `SELECT `+sessionColumns+` FROM sessions
		WHERE id = (SELECT session_id FROM access_tokens WHERE id = $1) AND expires_at > now()`, tokenID))
}
