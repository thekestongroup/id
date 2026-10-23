package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

// Memory fallbacks (used when KESTON_ID_DATABASE_URL is not set).
var (
	mu                    sync.Mutex
	memoryBackchannelURIs = map[string]string{}
	memoryRevokedSessions = map[string]time.Time{}
)

func backchannelLogoutURIs(ctx context.Context) (map[string]string, error) {
	if sqlStore != nil {
		return sqlStore.GetBackchannelLogoutURIs(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	out := map[string]string{}
	for k, v := range memoryBackchannelURIs {
		out[k] = v
	}
	return out, nil
}

func revokeSession(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	if sqlStore != nil {
		return sqlStore.RevokeSession(ctx, sid)
	}
	mu.Lock()
	defer mu.Unlock()
	memoryRevokedSessions[sid] = time.Now()
	return nil
}

func isSessionRevoked(ctx context.Context, sid string) (bool, error) {
	if sid == "" {
		return false, nil
	}
	if sqlStore != nil {
		return sqlStore.IsSessionRevoked(ctx, sid)
	}
	mu.Lock()
	defer mu.Unlock()
	_, ok := memoryRevokedSessions[sid]
	return ok, nil
}

// listRevokedSessions returns the revoked sessions an app server needs to
// (re)build its local blocked list, pruning entries older than the retention
// window.
func listRevokedSessions(ctx context.Context) ([]RevokedSession, error) {
	retention := cfg.AccessTokenLifespan + time.Minute
	if sqlStore != nil {
		return sqlStore.ListRevokedSessions(ctx, retention)
	}

	mu.Lock()
	defer mu.Unlock()
	cutoff := time.Now().Add(-retention)
	for sid, at := range memoryRevokedSessions {
		if at.Before(cutoff) {
			delete(memoryRevokedSessions, sid)
		}
	}
	out := make([]RevokedSession, 0, len(memoryRevokedSessions))
	for sid, at := range memoryRevokedSessions {
		out = append(out, RevokedSession{SID: sid, RevokedAt: at})
	}
	return out, nil
}

func revokedSessionsHandler(w http.ResponseWriter, r *http.Request) {
	sessions, err := listRevokedSessions(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
}

// logoutHandler clears the local session and propagates the logout to every
// relying party via OpenID Connect Back-Channel Logout.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := getSession(r)
	if ok {
		_ = revokeSession(r.Context(), sess.SID)
		go triggerBackchannelLogout(context.Background(), sess.Username, sess.SID)
	}

	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/", http.StatusFound)
}

func triggerBackchannelLogout(ctx context.Context, sub, sid string) {
	uris, err := backchannelLogoutURIs(ctx)
	if err != nil {
		log.Printf("back-channel logout: failed to list clients: %v", err)
		return
	}

	for clientID, uri := range uris {
		token, err := buildLogoutToken(clientID, sub, sid)
		if err != nil {
			log.Printf("back-channel logout: failed to build token for %s: %v", clientID, err)
			continue
		}

		form := url.Values{"logout_token": {token}}
		resp, err := http.Post(uri, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			log.Printf("back-channel logout: POST to %s failed: %v", uri, err)
			continue
		}
		resp.Body.Close()
		log.Printf("back-channel logout: sent to %s (client %s) -> %d", uri, clientID, resp.StatusCode)
	}
}

func buildLogoutToken(clientID, sub, sid string) (string, error) {
	claims := map[string]interface{}{
		"iss": cfg.Issuer,
		"sub": sub,
		"aud": clientID,
		"iat": time.Now().Unix(),
		"jti": randomID(),
		"events": map[string]interface{}{
			"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{},
		},
	}
	if sid != "" {
		claims["sid"] = sid
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// introspectHandler validates an access token (statelessly) and additionally
// checks the session revocation store so revoked sessions stop working
// immediately, even if their JWT access token is still within its lifetime.
func introspectHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := r.PostFormValue("token")
	if token == "" {
		token = bearerToken(r)
	}
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	tokenType, ar, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, newEmptySession())
	if err != nil || tokenType != fosite.AccessToken {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	session := ar.GetSession()
	sub := session.GetSubject()
	sid := ""
	extra := map[string]interface{}{}

	if jwts, ok := session.(*oauth2.JWTSession); ok {
		claims := jwts.GetJWTClaims().ToMapClaims()
		if v, ok := claims["sid"].(string); ok {
			sid = v
		}
		for _, key := range []string{"name", "email"} {
			if v, exists := claims[key]; exists {
				extra[key] = v
			}
		}
	}

	revoked, err := isSessionRevoked(ctx, sid)
	if err == nil && revoked {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active":    true,
		"sub":       sub,
		"sid":       sid,
		"scope":     strings.Join(ar.GetGrantedScopes(), " "),
		"client_id": ar.GetClient().GetID(),
		"name":      extra["name"],
		"email":     extra["email"],
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
