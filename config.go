package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

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

// loadPrivateKey returns the RSA signing key from KESTON_ID_RSA_PRIVATE_KEY
// (PEM, PKCS#1 or PKCS#8) if set, otherwise generates a fresh one. A stable key
// is required to keep stateless JWT access tokens valid across restarts.
func loadPrivateKey() *rsa.PrivateKey {
	if pemStr := os.Getenv("KESTON_ID_RSA_PRIVATE_KEY"); pemStr != "" {
		block, _ := pem.Decode([]byte(pemStr))
		if block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if key, ok := k.(*rsa.PrivateKey); ok {
					return key
				}
			}
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return key
			}
		}
		log.Fatal("failed to parse KESTON_ID_RSA_PRIVATE_KEY as a PEM RSA key")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}
	log.Println("no KESTON_ID_RSA_PRIVATE_KEY set — generated an ephemeral key (JWT access tokens will not survive a restart)")
	return key
}
