package main

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"golang.org/x/crypto/bcrypt"
)

//go:embed all:web/dist
var webFS embed.FS

var (
	privateKey *rsa.PrivateKey
	store      *storage.MemoryStore
	config     *fosite.Config
	provider   fosite.OAuth2Provider
)

func init() {
	var err error

	cfg = loadConfig()

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	store = storage.NewMemoryStore()

	clientSecretHash, err := bcrypt.GenerateFromPassword([]byte("keston-work-secret"), 10)
	if err != nil {
		log.Fatalf("failed to hash client secret: %v", err)
	}

	store.Clients["keston-work"] = &fosite.DefaultClient{
		ID:            "keston-work",
		Secret:        clientSecretHash,
		RedirectURIs:  []string{cfg.WorkRedirect},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Audience:      []string{"keston-work"},
	}

	store.Clients["keston-demo"] = &fosite.DefaultClient{
		ID:            "keston-demo",
		RedirectURIs:  []string{cfg.DemoRedirect},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Audience:      []string{"keston-demo"},
		Public:        true,
	}

	config = &fosite.Config{
		AccessTokenLifespan:         time.Hour,
		AuthorizeCodeLifespan:       time.Minute * 10,
		IDTokenLifespan:             time.Hour,
		RefreshTokenLifespan:        time.Hour * 24,
		GlobalSecret:                cfg.Secret,
		IDTokenIssuer:               cfg.Issuer,
		TokenURL:                    cfg.Issuer + "/token",
		SendDebugMessagesToClients:  true,
		EnforcePKCEForPublicClients: true,
	}

	provider = compose.ComposeAllEnabled(config, store, privateKey)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/userinfo", userinfoHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/consent", consentHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)
	mux.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	mux.HandleFunc("/", webHandler)

	addr := cfg.Addr
	log.Printf("Keston ID listening on %s (issuer %s)", addr, cfg.Issuer)
	log.Fatal(http.ListenAndServe(addr, corsMiddleware(mux)))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func distFS() (fs.FS, error) {
	return fs.Sub(webFS, "web/dist")
}

func serveIndex(w http.ResponseWriter) {
	sub, err := distFS()
	if err != nil {
		http.Error(w, "web assets not built", http.StatusInternalServerError)
		return
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "index.html not found (run the web build)", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(index)
}

func webHandler(w http.ResponseWriter, r *http.Request) {
	sub, err := distFS()
	if err != nil {
		http.Error(w, "web assets not built", http.StatusInternalServerError)
		return
	}
	if r.URL.Path == "/" {
		serveIndex(w)
		return
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
