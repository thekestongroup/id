package main

import (
	"crypto/hmac"
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
}

const sessionCookieName = "keston_session"

func sign(msg string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func setSession(w http.ResponseWriter, data sessionData) {
	payload, _ := json.Marshal(data)
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

func getSession(r *http.Request) (sessionData, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return sessionData{}, false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return sessionData{}, false
	}
	if !hmac.Equal([]byte(sign(parts[0])), []byte(parts[1])) {
		return sessionData{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return sessionData{}, false
	}
	var data sessionData
	if err := json.Unmarshal(payload, &data); err != nil {
		return sessionData{}, false
	}
	return data, true
}

func currentUser(r *http.Request) string {
	if data, ok := getSession(r); ok {
		return data.Username
	}
	return ""
}

func isConsented(r *http.Request) bool {
	data, ok := getSession(r)
	return ok && data.Consented
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

		if username == "admin" && password == "password" {
			setSession(w, sessionData{Username: username})
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

		data, ok := getSession(r)
		if !ok {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
			return
		}

		if action == "deny" {
			http.Redirect(w, r, buildAccessDeniedURL(returnTo), http.StatusFound)
			return
		}

		data.Consented = true
		setSession(w, data)
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
