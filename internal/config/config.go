// Package config reads Keston ID's settings from the environment, so the same
// image runs locally, in docker compose and (later) in Kubernetes.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/thekestongroup/id/internal/clientip"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Public address people and apps use, e.g. https://id.keston.co. Also the
	// OIDC issuer, so it must be the same on every replica.
	Issuer string
	// Address to listen on inside the container.
	Addr string
	// Postgres connection string.
	DatabaseURL string
	// 32 bytes, base64. Encrypts signing keys and MFA secrets in the
	// database, and opaque tokens. Same on every replica; keep it secret.
	SecretKey [32]byte
	// Lifetimes.
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
	SessionTTL      time.Duration
	AuthRequestTTL  time.Duration
	// Other sites allowed to call the API (/v1) from a browser with an access
	// token, e.g. https://admin.example.com. Exact origins, comma separated.
	// Empty: none (the web UI and same-origin proxies don't need any).
	APIOrigins []string
	// Dev only: proxy the web UI to the Vite dev server instead of serving
	// the embedded build, e.g. http://localhost:5180.
	DevWebURL string
	// Allow an http:// issuer (local development only).
	Insecure bool
	// The Keston Group's own organisation (the platform organisation), made
	// at start if it isn't there: its global admins are Keston staff.
	PlatformName   string
	PlatformDomain string
	// KESTON_ID_TRUSTED_PROXY: "none" (default; the client address is the
	// TCP peer) or "cloudflare" (trust CF-Connecting-IP behind the ingress).
	TrustedProxy clientip.Mode
}

func Load() (*Config, error) {
	c := &Config{
		Issuer:          strings.TrimRight(env("KESTON_ID_ISSUER", "http://id.keston.localhost:8080"), "/"),
		Addr:            env("KESTON_ID_ADDR", ":8080"),
		DatabaseURL:     env("KESTON_ID_DATABASE_URL", "postgres://keston:keston@localhost:5432/keston_id?sslmode=disable"),
		DevWebURL:       os.Getenv("KESTON_ID_DEV_WEB_URL"),
		PlatformName:    env("KESTON_ID_PLATFORM_NAME", "The Keston Group"),
		PlatformDomain:  env("KESTON_ID_PLATFORM_DOMAIN", "thekestongroup.com"),
		AccessTokenTTL:  15 * time.Minute,
		IDTokenTTL:      time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		SessionTTL:      14 * 24 * time.Hour,
		AuthRequestTTL:  30 * time.Minute,
	}
	tp, ok := clientip.Parse(os.Getenv("KESTON_ID_TRUSTED_PROXY"))
	if !ok {
		return nil, errors.New(`KESTON_ID_TRUSTED_PROXY must be "none" or "cloudflare"`)
	}
	c.TrustedProxy = tp
	c.Insecure = strings.HasPrefix(c.Issuer, "http://")
	for _, o := range strings.Split(os.Getenv("KESTON_ID_API_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			c.APIOrigins = append(c.APIOrigins, o)
		}
	}

	for name, target := range map[string]*time.Duration{
		"KESTON_ID_ACCESS_TOKEN_TTL":  &c.AccessTokenTTL,
		"KESTON_ID_ID_TOKEN_TTL":      &c.IDTokenTTL,
		"KESTON_ID_REFRESH_TOKEN_TTL": &c.RefreshTokenTTL,
		"KESTON_ID_SESSION_TTL":       &c.SessionTTL,
	} {
		if v := os.Getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			*target = d
		}
	}

	raw := os.Getenv("KESTON_ID_SECRET_KEY")
	if raw == "" {
		if !c.Insecure {
			return nil, errors.New("KESTON_ID_SECRET_KEY is required (32 random bytes, base64): openssl rand -base64 32")
		}
		// Local development only: a fixed key, so restarts keep working.
		raw = base64.StdEncoding.EncodeToString([]byte("keston-id-local-development-key!"))
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("KESTON_ID_SECRET_KEY must be 32 bytes, base64 encoded")
	}
	copy(c.SecretKey[:], key)
	return c, nil
}

// SecureCookies: cookies are only sent over HTTPS, except on a local http issuer.
func (c *Config) SecureCookies() bool { return !c.Insecure }

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
