package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed all:web/dist
var webFS embed.FS

//go:embed schema.sql
var schemaSQL string

var (
	privateKey *rsa.PrivateKey
	config     *fosite.Config
	provider   fosite.OAuth2Provider
	sqlStore   *SQLStore
	memStore   *storage.MemoryStore
)

func init() {
	cfg = loadConfig()
	privateKey = loadPrivateKey()

	config = &fosite.Config{
		AccessTokenLifespan:         cfg.AccessTokenLifespan,
		AuthorizeCodeLifespan:       time.Minute * 10,
		IDTokenLifespan:             time.Hour,
		RefreshTokenLifespan:        time.Hour * 24,
		GlobalSecret:                cfg.Secret,
		IDTokenIssuer:               cfg.Issuer,
		AccessTokenIssuer:           cfg.Issuer,
		TokenURL:                    cfg.Issuer + "/token",
		SendDebugMessagesToClients:  true,
		EnforcePKCEForPublicClients: true,
	}

	keyGetter := func(ctx context.Context) (interface{}, error) { return privateKey, nil }
	hmacStrategy := compose.NewOAuth2HMACStrategy(config)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, config)
	strategy := &compose.CommonStrategy{
		CoreStrategy:               jwtStrategy,
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}

	var storageImpl interface{}
	if cfg.DatabaseURL != "" {
		db, err := sql.Open("pgx", cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("failed to open database: %v", err)
		}
		if err := db.PingContext(context.Background()); err != nil {
			log.Fatalf("failed to connect to database: %v", err)
		}
		if err := migrate(db, schemaSQL); err != nil {
			log.Fatalf("failed to run migrations: %v", err)
		}
		s := NewSQLStore(db)
		if err := s.Seed(context.Background()); err != nil {
			log.Fatalf("failed to seed database: %v", err)
		}
		sqlStore = s
		storageImpl = s
	} else {
		log.Println("KESTON_ID_DATABASE_URL not set — using in-memory store")
		memStore = seedMemoryStore()
		storageImpl = memStore
	}

	provider = compose.Compose(
		config,
		storageImpl,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
	)
}

func migrate(db *sql.DB, schema string) error {
	for _, stmt := range strings.Split(schema, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return err
		}
	}
	return nil
}

func seedMemoryStore() *storage.MemoryStore {
	s := storage.NewMemoryStore()

	workSecret, err := bcrypt.GenerateFromPassword([]byte("keston-work-secret"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to hash client secret: %v", err)
	}

	s.Clients["keston-work"] = &fosite.DefaultClient{
		ID:            "keston-work",
		Secret:        workSecret,
		RedirectURIs:  []string{cfg.WorkRedirect},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Audience:      []string{"keston-work"},
	}

	s.Clients["keston-demo"] = &fosite.DefaultClient{
		ID:            "keston-demo",
		RedirectURIs:  []string{cfg.DemoRedirect},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"openid", "profile", "email", "offline_access"},
		Audience:      []string{"keston-demo"},
		Public:        true,
	}

	mu.Lock()
	memoryBackchannelURIs["keston-work"] = cfg.WorkLogoutURI
	mu.Unlock()

	return s
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/userinfo", userinfoHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/consent", consentHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/introspect", introspectHandler)
	mux.HandleFunc("/revoked-sessions", revokedSessionsHandler)
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
