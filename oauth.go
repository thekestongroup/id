package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ar, err := provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	if currentUser(r) == "" {
		http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	if !isConsented(r) {
		http.Redirect(w, r, "/consent?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}

	sess, _ := currentSession(r)
	response, err := provider.NewAuthorizeResponse(ctx, ar, newSession(sess.Username, ar.GetClient().GetID(), sess.SID))
	if err != nil {
		provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	provider.WriteAuthorizeResponse(ctx, w, ar, response)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accessRequest, err := provider.NewAccessRequest(ctx, r, newEmptySession())
	if err != nil {
		provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	response, err := provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	provider.WriteAccessResponse(ctx, w, accessRequest, response)
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := bearerToken(r)
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}

	tokenType, ar, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, newEmptySession())
	if err != nil || tokenType != fosite.AccessToken {
		writeJSONError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
		return
	}

	session := ar.GetSession()
	result := map[string]interface{}{"sub": session.GetSubject()}

	if jwts, ok := session.(*oauth2.JWTSession); ok {
		claims := jwts.GetJWTClaims().ToMapClaims()
		for _, key := range []string{"name", "email"} {
			if v, exists := claims[key]; exists {
				result[key] = v
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return auth[7:]
	}
	return ""
}

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
