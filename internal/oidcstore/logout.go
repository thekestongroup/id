package oidcstore

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/thekestongroup/id/internal/secret"
)

// backchannelEvent is the OpenID Connect Back-Channel Logout event.
const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// EndSession signs a Keston ID browser session out of every app it signed
// in to: their tokens stop working at once, and apps with a back-channel
// logout address are sent a signed logout token (OpenID Connect Back-Channel
// Logout 1.0), so they can end their own session for this person.
func (s *Storage) EndSession(ctx context.Context, sessionID string) error {
	apps, err := s.store.EndSessionApps(ctx, sessionID)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.BackchannelLogoutURI == "" {
			continue
		}
		token, err := s.logoutToken(ctx, app.ClientID, app.UserID, sessionID)
		if err != nil {
			slog.Warn("back-channel logout: signing", "client", app.ClientID, "error", err)
			continue
		}
		// Don't keep the person waiting on an app's server.
		go postLogout(app.ClientID, app.BackchannelLogoutURI, token)
	}
	return nil
}

func (s *Storage) logoutToken(ctx context.Context, clientID, userID, sessionID string) (string, error) {
	key, err := s.SigningKey(ctx)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: key.SignatureAlgorithm(), Key: key.Key()},
		(&jose.SignerOptions{}).WithType("logout+jwt").WithHeader("kid", key.ID()))
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	claims, err := json.Marshal(map[string]any{
		"iss":    s.cfg.Issuer,
		"aud":    clientID,
		"iat":    now,
		"exp":    now + 120,
		"jti":    secret.Token(),
		"sub":    userID,
		"sid":    sessionID,
		"events": map[string]any{backchannelEvent: map[string]any{}},
	})
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func postLogout(clientID, uri, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri,
		strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		slog.Warn("back-channel logout", "client", clientID, "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Warn("back-channel logout", "client", clientID, "error", err)
		return
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		slog.Warn("back-channel logout", "client", clientID, "status", res.StatusCode)
	}
}
