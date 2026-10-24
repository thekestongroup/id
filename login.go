package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type sessionData struct {
	Username  string `json:"u"`
	Consented bool   `json:"c"`
	SID       string `json:"sid"`
}

const sessionCookieName = "keston_sessions"

func sign(msg string) string {
	mac := hmac.New(sha256.New, cfg.Secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func setSessions(w http.ResponseWriter, sessions []sessionData) {
	payload, _ := json.Marshal(sessions)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	value := encoded + "." + sign(encoded)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
}

func getSessions(r *http.Request) []sessionData {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	if !hmac.Equal([]byte(sign(parts[0])), []byte(parts[1])) {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var sessions []sessionData
	if err := json.Unmarshal(payload, &sessions); err != nil {
		return nil
	}
	return sessions
}

func clearSessions(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, MaxAge: -1, Path: "/"})
}

// currentSession returns the active session (the last one in the list).
func currentSession(r *http.Request) (sessionData, bool) {
	sessions := getSessions(r)
	if len(sessions) == 0 {
		return sessionData{}, false
	}
	return sessions[len(sessions)-1], true
}

func currentUser(r *http.Request) string {
	if data, ok := currentSession(r); ok {
		return data.Username
	}
	return ""
}

func isConsented(r *http.Request) bool {
	data, ok := currentSession(r)
	return ok && data.Consented
}

// addSession adds (or replaces) a session for the given user and makes it active.
func addSession(w http.ResponseWriter, r *http.Request, username string) {
	sessions := getSessions(r)
	filtered := sessions[:0]
	for _, s := range sessions {
		if s.Username != username {
			filtered = append(filtered, s)
		}
	}
	filtered = append(filtered, sessionData{Username: username, SID: randomID()})
	setSessions(w, filtered)
}

// removeSession removes the session with the given sid.
func removeSession(w http.ResponseWriter, r *http.Request, sid string) {
	sessions := getSessions(r)
	filtered := sessions[:0]
	for _, s := range sessions {
		if s.SID != sid {
			filtered = append(filtered, s)
		}
	}
	setSessions(w, filtered)
}

// markActiveConsented marks the active session as consented.
func markActiveConsented(w http.ResponseWriter, r *http.Request) {
	sessions := getSessions(r)
	if len(sessions) == 0 {
		return
	}
	sessions[len(sessions)-1].Consented = true
	setSessions(w, sessions)
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func authenticateUser(ctx context.Context, username, password string) bool {
	if sqlStore != nil {
		return sqlStore.AuthenticateUser(ctx, username, password) == nil
	}
	mu.Lock()
	defer mu.Unlock()
	u, ok := memoryUsers[username]
	return ok && u.Password == password
}

func safeReturnTo(raw string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	return raw
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		serveIndex(w)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")
		returnTo := safeReturnTo(r.PostForm.Get("return_to"))

		if authenticateUser(r.Context(), username, password) {
			addSession(w, r, username)
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}

		http.Redirect(w, r, "/login?error=invalid&return_to="+url.QueryEscape(returnTo), http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func consentHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		serveIndex(w)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		returnTo := safeReturnTo(r.PostForm.Get("return_to"))
		action := r.PostForm.Get("action")

		if _, ok := currentSession(r); !ok {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
			return
		}

		if action == "deny" {
			http.Redirect(w, r, buildAccessDeniedURL(returnTo), http.StatusFound)
			return
		}

		markActiveConsented(w, r)
		http.Redirect(w, r, returnTo, http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func buildAccessDeniedURL(returnTo string) string {
	ru, err := url.ParseRequestURI(returnTo)
	if err != nil {
		return returnTo
	}
	q := ru.Query()
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	if redirectURI == "" {
		return returnTo
	}
	target := redirectURI + "?error=access_denied"
	if state != "" {
		target += "&state=" + url.QueryEscape(state)
	}
	return target
}
