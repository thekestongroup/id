//go:build e2e

// Tokens are never issued or refreshed for people in an unverified
// organisation, against a real Postgres:
//
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55420/keston_id?sslmode=disable \
//	  go test -tags e2e ./internal/oidcstore/
package oidcstore

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

func TestNoTokensForUnverifiedOrganisation(t *testing.T) {
	url := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KESTON_ID_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris)
		VALUES ('admin', 'Keston Admin', 'The Keston Group', '{}') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	st := store.New(pool, nil)
	s := New(st, &config.Config{AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour})

	domain := "t" + strings.ToLower(secret.Token()[:10]) + ".test"
	org, user, err := st.CreateOrganisationWith(ctx, "Unverified", domain, store.NewUser{
		Email: "admin@" + domain, Name: "Admin", PasswordHash: secret.HashPassword("x")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if org.Verified {
		t.Fatal("organisation should be unverified")
	}
	// A refresh token that already exists (say, issued before) stops working too.
	refresh, _, err := st.CreateRefreshToken(ctx, st.DB, &store.RefreshToken{ClientID: "admin", UserID: user.ID,
		Audience: []string{"admin"}, Scopes: []string{"openid"}, AMR: []string{"pwd"}, AuthTime: time.Now()}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := &refreshRequest{RefreshToken: &store.RefreshToken{ClientID: "admin", UserID: user.ID,
		Audience: []string{"admin"}, Scopes: []string{"openid"}, AMR: []string{"pwd"}, AuthTime: time.Now()}, token: refresh}

	if _, _, err := s.CreateAccessToken(ctx, req); err == nil {
		t.Error("access token issued for an unverified organisation")
	}
	if _, _, _, err := s.CreateAccessAndRefreshTokens(ctx, req, ""); err == nil {
		t.Error("token pair issued for an unverified organisation")
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err == nil {
		t.Error("refresh token accepted for an unverified organisation")
	}

	// Verified: all of it works.
	if _, err := st.VerifyOrganisation(ctx, org.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateAccessToken(ctx, req); err != nil {
		t.Errorf("access token after verifying: %v", err)
	}
	if _, err := s.TokenRequestByRefreshToken(ctx, refresh); err != nil {
		t.Errorf("refresh after verifying: %v", err)
	}
	if _, _, _, err := s.CreateAccessAndRefreshTokens(ctx, req, refresh); err != nil {
		t.Errorf("token pair after verifying: %v", err)
	}
}
