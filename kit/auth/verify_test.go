package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const issuer = "http://id.test"

func newKey(t *testing.T, id string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, jose.JSONWebKey{Key: &k.PublicKey, KeyID: id, Algorithm: "RS256", Use: "sig"}
}

func sign(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func good() map[string]any {
	return map[string]any{
		"iss": issuer, "sub": "user-1", "aud": []string{"admin", AudienceKestonID, "work"},
		"exp": time.Now().Add(10 * time.Minute).Unix(), "client_id": "admin", "jti": "t1",
		"org": "org-1", "perms": []string{"users.view", "users.reset_password"}, "platform_admin": false,
	}
}

func TestVerify(t *testing.T) {
	key, pub := newKey(t, "k1")
	other, _ := newKey(t, "k1")
	v := NewVerifier(issuer, "work", StaticKeys{pub})
	ctx := context.Background()

	c, err := v.Verify(ctx, sign(t, key, "k1", good()))
	if err != nil {
		t.Fatalf("good token: %v", err)
	}
	if c.Subject != "user-1" || c.Organisation != "org-1" || !c.Can("users.view") || c.Can("users.status") ||
		!c.CanIn("org-1", "users.reset_password") || c.CanIn("org-2", "users.view") || c.ClientID != "admin" {
		t.Errorf("claims: %+v", c)
	}

	cases := map[string]struct {
		edit func(map[string]any)
		key  *rsa.PrivateKey
		want error
	}{
		"other API's token": {func(m map[string]any) { m["aud"] = "learn" }, key, ErrAudience},
		"single aud string": {func(m map[string]any) { m["aud"] = "work" }, key, nil},
		"wrong issuer":      {func(m map[string]any) { m["iss"] = "http://evil.test" }, key, ErrIssuer},
		"expired":           {func(m map[string]any) { m["exp"] = time.Now().Add(-2 * time.Minute).Unix() }, key, ErrExpired},
		"within leeway":     {func(m map[string]any) { m["exp"] = time.Now().Add(-30 * time.Second).Unix() }, key, nil},
		"no expiry":         {func(m map[string]any) { delete(m, "exp") }, key, ErrExpired},
		"not yet valid":     {func(m map[string]any) { m["nbf"] = time.Now().Add(5 * time.Minute).Unix() }, key, ErrExpired},
		"forged signature":  {func(map[string]any) {}, other, ErrSignature},
	}
	for name, tc := range cases {
		claims := good()
		tc.edit(claims)
		_, err := v.Verify(ctx, sign(t, tc.key, "k1", claims))
		if err != tc.want {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
	if _, err := v.Verify(ctx, "not.a.token"); err != ErrMalformed {
		t.Errorf("garbage: %v", err)
	}
}

func TestRemoteKeysRotation(t *testing.T) {
	k1, pub1 := newKey(t, "k1")
	k2, pub2 := newKey(t, "k2")
	published := []jose.JSONWebKey{pub1}
	fetches := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		fetches++
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: published})
	}))
	defer srv.Close()

	keys := NewRemoteKeys(srv.URL)
	claims := good()
	claims["iss"] = srv.URL
	v := NewVerifier(srv.URL, "work", keys)
	ctx := context.Background()
	if _, err := v.Verify(ctx, sign(t, k1, "k1", claims)); err != nil {
		t.Fatalf("k1: %v", err)
	}
	if _, err := v.Verify(ctx, sign(t, k1, "k1", claims)); err != nil || fetches != 1 {
		t.Fatalf("cached: %v, %d fetches", err, fetches)
	}
	// Keston ID rotates to k2: the first k2 token triggers one refetch.
	published = []jose.JSONWebKey{pub2, pub1}
	keys.fetched = time.Now().Add(-time.Minute)
	if _, err := v.Verify(ctx, sign(t, k2, "k2", claims)); err != nil || fetches != 2 {
		t.Fatalf("rotated: %v, %d fetches", err, fetches)
	}
}

func TestMiddleware(t *testing.T) {
	key, pub := newKey(t, "k1")
	v := NewVerifier(issuer, "work", StaticKeys{pub})
	h := Middleware(v)(Require("users.view")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(FromContext(r.Context()).Subject))
	})))
	run := func(auth string) int {
		req := httptest.NewRequest("GET", "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := run(""); c != 401 {
		t.Errorf("no token: %d", c)
	}
	if c := run("Bearer " + sign(t, key, "k1", good())); c != 200 {
		t.Errorf("good: %d", c)
	}
	claims := good()
	claims["perms"] = []string{"apps.manage"}
	if c := run("Bearer " + sign(t, key, "k1", claims)); c != 403 {
		t.Errorf("missing permission: %d", c)
	}
}
