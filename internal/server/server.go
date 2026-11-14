// Package server puts Keston ID together: zitadel/oidc's endpoints, the web
// UI's JSON API, the web UI itself and health checks.
package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"

	"github.com/thekestongroup/id/internal/adminapi"
	"github.com/thekestongroup/id/internal/api"
	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/oidcstore"
	"github.com/thekestongroup/id/internal/store"
)

func New(cfg *config.Config, st *store.Store, storage *oidcstore.Storage, webFS fs.FS) (http.Handler, error) {
	opts := []op.Option{op.WithLogger(slog.Default())}
	if cfg.Insecure {
		opts = append(opts, op.WithAllowInsecure())
	}
	provider, err := op.NewProvider(&op.Config{
		CryptoKey:                cfg.SecretKey,
		DefaultLogoutRedirectURI: "/signed-out",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedUILocales:       []language.Tag{language.BritishEnglish},
		SupportedScopes:          []string{"openid", "profile", "email", "offline_access"},
		SupportedClaims: []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "acr", "amr", "c_hash",
			"at_hash", "name", "preferred_username", "email", "email_verified", "organisation", "updated_at"},
	}, storage, op.StaticIssuer(cfg.Issuer), opts...)
	if err != nil {
		return nil, err
	}

	a := api.New(st, cfg)
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer, requestLog, securityHeaders)

	// Liveness and readiness for docker / the load balancer / Kubernetes.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := storage.Health(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})

	r.Mount("/api", a.Routes())

	// Keston Admin's API. Caddy serves it at admin.keston.co/api/…, so the
	// admin app calls it on its own origin (no CORS).
	verify := func(ctx context.Context, token string) (*oidc.AccessTokenClaims, error) {
		v := provider.AccessTokenVerifier(op.ContextWithIssuer(ctx, cfg.Issuer))
		return op.VerifyAccessToken[*oidc.AccessTokenClaims](ctx, token, v)
	}
	r.Mount("/admin/v1", adminapi.New(st, verify).Routes())

	// Cancel on the consent prompt, or prompt=none that needs interaction:
	// send the OAuth error back to the app.
	r.Get("/authorize/deny", func(w http.ResponseWriter, r *http.Request) {
		authReq, err := storage.AuthRequestByID(r.Context(), r.URL.Query().Get("id"))
		if err != nil {
			op.AuthRequestError(w, r, nil, err, provider)
			return
		}
		var reason error
		switch r.URL.Query().Get("error") {
		case "login_required":
			reason = oidc.ErrLoginRequired()
		case "consent_required":
			e := oidc.ErrInteractionRequired()
			e.ErrorType = "consent_required" // the library has no constructor for it
			reason = e
		default:
			reason = oidc.ErrAccessDenied().WithDescription("The user didn't allow access.")
		}
		_ = storage.DeleteAuthRequest(r.Context(), authReq.GetID())
		op.AuthRequestError(w, r, authReq, reason, provider)
	})

	// Signing out of an app through end_session also signs the browser out
	// of Keston ID.
	oidcHandler := http.Handler(provider)
	r.HandleFunc("/end_session", func(w http.ResponseWriter, r *http.Request) {
		a.EndBrowserSession(w, r)
		oidcHandler.ServeHTTP(w, r)
	})

	// OIDC: discovery, /authorize (+ /authorize/callback), /oauth/token,
	// /userinfo, /keys, /revoke, /oauth/introspect.
	for _, p := range []string{"/.well-known/*", "/authorize", "/authorize/callback", "/oauth/*", "/userinfo",
		"/keys", "/revoke"} {
		r.Handle(p, oidcHandler)
	}

	// Everything else is the web UI.
	if cfg.DevWebURL != "" {
		target, err := url.Parse(cfg.DevWebURL)
		if err != nil {
			return nil, err
		}
		r.Handle("/*", httputil.NewSingleHostReverseProxy(target))
	} else {
		r.Handle("/*", spa(webFS))
	}
	return r, nil
}

// spa serves built files, and index.html for the UI's own routes.
func spa(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		index = []byte("Keston ID: the web UI hasn't been built. Run pnpm build in web/.")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if _, err := fs.Stat(files, name); err == nil {
				if strings.HasPrefix(name, "assets/") {
					// Hashed file names: safe to cache for a year.
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				fileServer.ServeHTTP(w, r)
				return
			} else if !errors.Is(err, fs.ErrNotExist) || path.Ext(name) != "" {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(index)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// The sign-in pages must never be framed (clickjacking).
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(), "request_id", middleware.GetReqID(r.Context()))
	})
}
