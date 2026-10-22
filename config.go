package main

import "os"

// Config holds runtime configuration, sourced from environment variables
// (with dev-friendly defaults so `go run .` works out of the box).
type Config struct {
	Issuer       string
	Addr         string
	Secret       []byte
	WorkRedirect string
	DemoRedirect string
	DatabaseURL  string
}

var cfg *Config

func loadConfig() *Config {
	secret := envOr("KESTON_ID_SECRET", "0123456789abcdef0123456789abcdef")
	for len(secret) < 32 {
		secret += "0"
	}
	if len(secret) > 32 {
		secret = secret[:32]
	}

	return &Config{
		Issuer:       envOr("KESTON_ID_ISSUER", "http://localhost:4444"),
		Addr:         envOr("KESTON_ID_ADDR", ":4444"),
		Secret:       []byte(secret),
		WorkRedirect: envOr("KESTON_ID_WORK_REDIRECT_URI", "http://localhost:3000/callback"),
		DemoRedirect: envOr("KESTON_ID_DEMO_REDIRECT_URI", "http://localhost:3000/callback"),
		DatabaseURL:  os.Getenv("KESTON_ID_DATABASE_URL"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
