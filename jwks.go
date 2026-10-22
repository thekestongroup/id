package main

import (
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v3"
)

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	key := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     "keston-id-key",
		Algorithm: "RS256",
		Use:       "sig",
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(set)
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	doc := map[string]interface{}{
		"issuer":                                cfg.Issuer,
		"authorization_endpoint":                cfg.Issuer + "/authorize",
		"token_endpoint":                        cfg.Issuer + "/token",
		"userinfo_endpoint":                     cfg.Issuer + "/userinfo",
		"jwks_uri":                              cfg.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
