package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"
)

// SQLStore implements the fosite storage interfaces backed by Postgres.
// Access tokens are stateless JWTs and are NOT persisted; refresh tokens,
// authorize codes, OIDC sessions, PKCE sessions, clients and users are.
type SQLStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

// dber is satisfied by both *sql.DB and *sql.Tx.
type dber interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

type txKey struct{}

func (s *SQLStore) conn(ctx context.Context) dber {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

func (s *SQLStore) BeginTX(ctx context.Context) (context.Context, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, txKey{}, tx), nil
}

func (s *SQLStore) Commit(ctx context.Context) error {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx.Commit()
	}
	return nil
}

func (s *SQLStore) Rollback(ctx context.Context) error {
	if tx, ok := ctx.Value(txKey{}).(*sql.Tx); ok {
		return tx.Rollback()
	}
	return nil
}

// --- Request serialization ---------------------------------------------------

type storedSession struct {
	JWTClaims *jwt.JWTClaims                 `json:"jwt_claims"`
	JWTHeader *jwt.Headers                   `json:"jwt_header"`
	ExpiresAt map[fosite.TokenType]time.Time `json:"expires_at"`
	Username  string                         `json:"username"`
	Subject   string                         `json:"subject"`
	IDClaims  *jwt.IDTokenClaims             `json:"id_token_claims"`
	IDHeaders *jwt.Headers                   `json:"id_token_headers"`
}

type storedRequest struct {
	ID                string           `json:"id"`
	RequestedAt       time.Time        `json:"requested_at"`
	ClientID          string           `json:"client_id"`
	RequestedScope    fosite.Arguments `json:"requested_scope"`
	GrantedScope      fosite.Arguments `json:"granted_scope"`
	Form              url.Values       `json:"form"`
	Session           *storedSession   `json:"session"`
	RequestedAudience fosite.Arguments `json:"requested_audience"`
	GrantedAudience   fosite.Arguments `json:"granted_audience"`
}

func toStoredSession(s fosite.Session) *storedSession {
	if sess, ok := s.(*Session); ok {
		return &storedSession{
			JWTClaims: sess.JWTSession.JWTClaims,
			JWTHeader: sess.JWTSession.JWTHeader,
			ExpiresAt: sess.JWTSession.ExpiresAt,
			Username:  sess.JWTSession.Username,
			Subject:   sess.JWTSession.Subject,
			IDClaims:  sess.IDClaims,
			IDHeaders: sess.IDHeaders,
		}
	}
	return &storedSession{}
}

func (ss *storedSession) toSession() *Session {
	if ss == nil {
		return &Session{
			JWTSession: &oauth2.JWTSession{},
			IDClaims:   &jwt.IDTokenClaims{},
			IDHeaders:  &jwt.Headers{},
		}
	}
	return &Session{
		JWTSession: &oauth2.JWTSession{
			JWTClaims: ss.JWTClaims,
			JWTHeader: ss.JWTHeader,
			ExpiresAt: ss.ExpiresAt,
			Username:  ss.Username,
			Subject:   ss.Subject,
		},
		IDClaims:  ss.IDClaims,
		IDHeaders: ss.IDHeaders,
	}
}

func marshalRequest(r fosite.Requester) ([]byte, error) {
	sr := storedRequest{
		ID:                r.GetID(),
		RequestedAt:       r.GetRequestedAt(),
		ClientID:          r.GetClient().GetID(),
		RequestedScope:    r.GetRequestedScopes(),
		GrantedScope:      r.GetGrantedScopes(),
		Form:              r.GetRequestForm(),
		Session:           toStoredSession(r.GetSession()),
		RequestedAudience: r.GetRequestedAudience(),
		GrantedAudience:   r.GetGrantedAudience(),
	}
	return json.Marshal(sr)
}

func (s *SQLStore) unmarshalRequest(ctx context.Context, data []byte) (fosite.Requester, error) {
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	client, err := s.GetClient(ctx, sr.ClientID)
	if err != nil {
		return nil, err
	}
	return &fosite.Request{
		ID:                sr.ID,
		RequestedAt:       sr.RequestedAt,
		Client:            client,
		RequestedScope:    sr.RequestedScope,
		GrantedScope:      sr.GrantedScope,
		Form:              sr.Form,
		Session:           sr.Session.toSession(),
		RequestedAudience: sr.RequestedAudience,
		GrantedAudience:   sr.GrantedAudience,
	}, nil
}

// --- ClientManager -----------------------------------------------------------

func (s *SQLStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var (
		secret        string
		redirectURIs  string
		grantTypes    string
		responseTypes string
		scopes        string
		audience      string
		public        bool
	)
	err := s.conn(ctx).QueryRowContext(ctx,
		`SELECT secret, redirect_uris, grant_types, response_types, scopes, audience, public FROM clients WHERE id = $1`,
		id,
	).Scan(&secret, &redirectURIs, &grantTypes, &responseTypes, &scopes, &audience, &public)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound.WithHint("client not found")
	}
	if err != nil {
		return nil, err
	}

	return &fosite.DefaultClient{
		ID:            id,
		Secret:        []byte(secret),
		RedirectURIs:  parseStrings(redirectURIs),
		GrantTypes:    fosite.Arguments(parseStrings(grantTypes)),
		ResponseTypes: fosite.Arguments(parseStrings(responseTypes)),
		Scopes:        fosite.Arguments(parseStrings(scopes)),
		Audience:      fosite.Arguments(parseStrings(audience)),
		Public:        public,
	}, nil
}

func (s *SQLStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var count int
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM client_assertion_jti WHERE jti = $1 AND expires_at > now()`, jti).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *SQLStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.conn(ctx).ExecContext(ctx,
		`INSERT INTO client_assertion_jti (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`,
		jti, exp,
	)
	return err
}

// --- AuthorizeCodeStorage ----------------------------------------------------

func (s *SQLStore) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	data, err := marshalRequest(request)
	if err != nil {
		return err
	}
	_, err = s.conn(ctx).ExecContext(ctx,
		`INSERT INTO authorize_codes (code, request, active) VALUES ($1, $2, TRUE) ON CONFLICT (code) DO UPDATE SET request = EXCLUDED.request, active = TRUE`,
		code, string(data),
	)
	return err
}

func (s *SQLStore) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	var (
		data   string
		active bool
	)
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT request, active FROM authorize_codes WHERE code = $1`, code).Scan(&data, &active)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	req, err := s.unmarshalRequest(ctx, []byte(data))
	if err != nil {
		return nil, err
	}
	if !active {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	return req, nil
}

func (s *SQLStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `UPDATE authorize_codes SET active = FALSE WHERE code = $1`, code)
	return err
}

// --- AccessTokenStorage (stateless JWTs — not persisted) ---------------------

func (s *SQLStore) CreateAccessTokenSession(_ context.Context, _ string, _ fosite.Requester) error {
	return nil
}

func (s *SQLStore) GetAccessTokenSession(_ context.Context, _ string, _ fosite.Session) (fosite.Requester, error) {
	return nil, fosite.ErrNotFound
}

func (s *SQLStore) DeleteAccessTokenSession(_ context.Context, _ string) error {
	return nil
}

// --- RefreshTokenStorage -----------------------------------------------------

func (s *SQLStore) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request fosite.Requester) error {
	data, err := marshalRequest(request)
	if err != nil {
		return err
	}
	_, err = s.conn(ctx).ExecContext(ctx,
		`INSERT INTO refresh_tokens (signature, request_id, request, active) VALUES ($1, $2, $3, TRUE)`,
		signature, request.GetID(), string(data),
	)
	return err
}

func (s *SQLStore) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	var (
		data   string
		active bool
	)
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT request, active FROM refresh_tokens WHERE signature = $1`, signature).Scan(&data, &active)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	req, err := s.unmarshalRequest(ctx, []byte(data))
	if err != nil {
		return nil, err
	}
	if !active {
		return req, fosite.ErrInactiveToken
	}
	return req, nil
}

func (s *SQLStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `DELETE FROM refresh_tokens WHERE signature = $1`, signature)
	return err
}

func (s *SQLStore) RotateRefreshToken(ctx context.Context, requestID, refreshTokenSignature string) error {
	// Deactivate the existing refresh token(s) for this request; the new one is
	// created by CreateRefreshTokenSession afterwards.
	_, err := s.conn(ctx).ExecContext(ctx,
		`UPDATE refresh_tokens SET active = FALSE WHERE request_id = $1`,
		requestID,
	)
	return err
}

// --- TokenRevocationStorage --------------------------------------------------

func (s *SQLStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	res, err := s.conn(ctx).ExecContext(ctx, `UPDATE refresh_tokens SET active = FALSE WHERE request_id = $1`, requestID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fosite.ErrNotFound
	}
	return nil
}

func (s *SQLStore) RevokeAccessToken(_ context.Context, _ string) error {
	// Stateless JWT access tokens cannot be revoked.
	return nil
}

// --- OpenIDConnectRequestStorage ---------------------------------------------

func (s *SQLStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	data, err := marshalRequest(request)
	if err != nil {
		return err
	}
	_, err = s.conn(ctx).ExecContext(ctx,
		`INSERT INTO oidc_sessions (authorize_code, request) VALUES ($1, $2) ON CONFLICT (authorize_code) DO UPDATE SET request = EXCLUDED.request`,
		authorizeCode, string(data),
	)
	return err
}

func (s *SQLStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, _ fosite.Requester) (fosite.Requester, error) {
	var data string
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT request FROM oidc_sessions WHERE authorize_code = $1`, authorizeCode).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.unmarshalRequest(ctx, []byte(data))
}

func (s *SQLStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `DELETE FROM oidc_sessions WHERE authorize_code = $1`, authorizeCode)
	return err
}

// --- PKCERequestStorage ------------------------------------------------------

func (s *SQLStore) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	data, err := marshalRequest(request)
	if err != nil {
		return err
	}
	_, err = s.conn(ctx).ExecContext(ctx,
		`INSERT INTO pkce_sessions (signature, request) VALUES ($1, $2) ON CONFLICT (signature) DO UPDATE SET request = EXCLUDED.request`,
		signature, string(data),
	)
	return err
}

func (s *SQLStore) GetPKCERequestSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	var data string
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT request FROM pkce_sessions WHERE signature = $1`, signature).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.unmarshalRequest(ctx, []byte(data))
}

func (s *SQLStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `DELETE FROM pkce_sessions WHERE signature = $1`, signature)
	return err
}

// --- Users -------------------------------------------------------------------

func (s *SQLStore) AuthenticateUser(ctx context.Context, username, password string) error {
	var hash, status string
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT password_hash, status FROM users WHERE username = $1`, username).Scan(&hash, &status)
	if err == sql.ErrNoRows {
		return fosite.ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "" && status != "active" {
		return fosite.ErrNotFound.WithHint("account disabled")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return fosite.ErrNotFound.WithHint("invalid credentials")
	}
	return nil
}

// User is a Keston ID user (login identifier is the username/email).
type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Status   string `json:"status"`
}

func (s *SQLStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.conn(ctx).QueryContext(ctx, `SELECT username, name, email, status FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Username, &u.Name, &u.Email, &u.Status); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateUser(ctx context.Context, username, passwordHash, name, email string) error {
	res, err := s.conn(ctx).ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, name, email) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (username) DO NOTHING`,
		randomID(), username, passwordHash, name, email,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("user already exists")
	}
	return nil
}

func (s *SQLStore) UpdateUser(ctx context.Context, username, name, email string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `UPDATE users SET name = $1, email = $2 WHERE username = $3`, name, email, username)
	return err
}

func (s *SQLStore) DeleteUser(ctx context.Context, username string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `DELETE FROM users WHERE username = $1`, username)
	return err
}

func (s *SQLStore) SetUserPassword(ctx context.Context, username, passwordHash string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `UPDATE users SET password_hash = $1 WHERE username = $2`, passwordHash, username)
	return err
}

func (s *SQLStore) SetUserStatus(ctx context.Context, username, status string) error {
	_, err := s.conn(ctx).ExecContext(ctx, `UPDATE users SET status = $1 WHERE username = $2`, status, username)
	return err
}

func (s *SQLStore) GetUserInfo(ctx context.Context, username string) (name, email string, err error) {
	err = s.conn(ctx).QueryRowContext(ctx, `SELECT name, email FROM users WHERE username = $1`, username).Scan(&name, &email)
	return
}

// --- Helpers -----------------------------------------------------------------

func parseStrings(raw string) []string {
	var out []string
	if raw == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func encodeStrings(in []string) string {
	data, _ := json.Marshal(in)
	return string(data)
}

// Seed inserts the demo user and OAuth clients, idempotently.
func (s *SQLStore) Seed(ctx context.Context) error {
	adminHash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, name, email) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (username) DO NOTHING`,
		"admin", "admin", string(adminHash), "Administrator", "admin@keston.local",
	); err != nil {
		return err
	}

	workSecret, err := bcrypt.GenerateFromPassword([]byte("keston-work-secret"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, audience, public, backchannel_logout_uri)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
		 ON CONFLICT (id) DO NOTHING`,
		"keston-work", string(workSecret), encodeStrings([]string{cfg.WorkRedirect}),
		encodeStrings([]string{"authorization_code", "refresh_token"}),
		encodeStrings([]string{"code"}),
		encodeStrings([]string{"openid", "profile", "email", "offline_access"}),
		encodeStrings([]string{"keston-work"}),
		cfg.WorkLogoutURI,
	); err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, audience, public, backchannel_logout_uri)
		 VALUES ($1, '', $2, $3, $4, $5, $6, TRUE, '')
		 ON CONFLICT (id) DO NOTHING`,
		"keston-demo", encodeStrings([]string{cfg.DemoRedirect}),
		encodeStrings([]string{"authorization_code", "refresh_token"}),
		encodeStrings([]string{"code"}),
		encodeStrings([]string{"openid", "profile", "email", "offline_access"}),
		encodeStrings([]string{"keston-demo"}),
	); err != nil {
		return err
	}

	adminSecret, err := bcrypt.GenerateFromPassword([]byte("keston-admin-secret"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, audience, public, backchannel_logout_uri)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
		 ON CONFLICT (id) DO NOTHING`,
		"keston-admin", string(adminSecret), encodeStrings([]string{cfg.AdminRedirect}),
		encodeStrings([]string{"authorization_code", "refresh_token"}),
		encodeStrings([]string{"code"}),
		encodeStrings([]string{"openid", "profile", "email", "offline_access"}),
		encodeStrings([]string{"keston-admin"}),
		cfg.AdminLogoutURI,
	); err != nil {
		return err
	}

	return nil
}

// GetBackchannelLogoutURIs returns the back-channel logout URI for each client
// that registered one, keyed by client ID.
func (s *SQLStore) GetBackchannelLogoutURIs(ctx context.Context) (map[string]string, error) {
	rows, err := s.conn(ctx).QueryContext(ctx, `SELECT id, backchannel_logout_uri FROM clients WHERE backchannel_logout_uri <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id, uri string
		if err := rows.Scan(&id, &uri); err != nil {
			return nil, err
		}
		out[id] = uri
	}
	return out, rows.Err()
}

// RevokeSession records a session ID as revoked.
func (s *SQLStore) RevokeSession(ctx context.Context, sid string) error {
	_, err := s.conn(ctx).ExecContext(ctx,
		`INSERT INTO revoked_sessions (sid, revoked_at) VALUES ($1, now()) ON CONFLICT (sid) DO NOTHING`, sid,
	)
	return err
}

// IsSessionRevoked reports whether the session ID has been revoked.
func (s *SQLStore) IsSessionRevoked(ctx context.Context, sid string) (bool, error) {
	var count int
	err := s.conn(ctx).QueryRowContext(ctx, `SELECT COUNT(*) FROM revoked_sessions WHERE sid = $1`, sid).Scan(&count)
	return count > 0, err
}

// RevokedSession is a revoked session ID with the time it was revoked.
type RevokedSession struct {
	SID       string    `json:"sid"`
	RevokedAt time.Time `json:"revoked_at"`
}

// ListRevokedSessions returns revoked sessions newer than the retention window,
// pruning anything older (they only matter until the access token would have
// expired anyway).
func (s *SQLStore) ListRevokedSessions(ctx context.Context, retention time.Duration) ([]RevokedSession, error) {
	cutoff := time.Now().Add(-retention)
	if _, err := s.conn(ctx).ExecContext(ctx, `DELETE FROM revoked_sessions WHERE revoked_at < $1`, cutoff); err != nil {
		return nil, err
	}

	rows, err := s.conn(ctx).QueryContext(ctx, `SELECT sid, revoked_at FROM revoked_sessions ORDER BY revoked_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RevokedSession
	for rows.Next() {
		var rs RevokedSession
		if err := rows.Scan(&rs.SID, &rs.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}
