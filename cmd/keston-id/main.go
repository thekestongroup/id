// Keston ID: the OpenID Connect identity provider for every Keston app.
//
//	keston-id                       serve (migrates and creates a signing key first)
//	keston-id migrate               apply database migrations and exit
//	keston-id clients sync FILE     register / update apps from a JSON file
//	keston-id users create          create an account (password from KESTON_ID_PASSWORD or stdin)
//	keston-id healthcheck           exit 0 if this container is ready (for docker)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/thekestongroup/id/internal/config"
	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/oidcstore"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/server"
	"github.com/thekestongroup/id/internal/store"
	"github.com/thekestongroup/id/web"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(os.Args[1:]); err != nil {
		slog.Error("keston-id", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// The image has no shell or curl, so docker's healthcheck runs this.
	if len(args) > 0 && args[0] == "healthcheck" {
		return healthcheck()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	box, err := secret.NewBox(cfg.SecretKey)
	if err != nil {
		return err
	}
	st := store.New(pool, box)

	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve(ctx, cfg, pool, st)
	case "migrate":
		return nil // done above
	case "clients":
		if len(args) != 2 || args[0] != "sync" {
			return errors.New("usage: keston-id clients sync FILE")
		}
		return syncClients(ctx, st, args[1])
	case "users":
		if len(args) == 0 || args[0] != "create" {
			return errors.New("usage: keston-id users create -email … -name … [-organisation …]")
		}
		return createUser(ctx, st, args[1:])
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func serve(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool, st *store.Store) error {
	storage := oidcstore.New(st, cfg)
	ensureKey := func() error {
		return db.WithLock(ctx, pool, 4_441_945, func() error { return storage.EnsureSigningKey(ctx) })
	}
	if err := ensureKey(); err != nil {
		return fmt.Errorf("signing key: %w", err)
	}

	handler, err := server.New(cfg, st, storage, web.Dist())
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// Housekeeping: delete expired rows and rotate the signing key when it's
	// due. Every replica runs it; both jobs are safe to run concurrently.
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := st.Cleanup(ctx); err != nil {
					slog.Warn("cleanup", "error", err)
				}
				if err := ensureKey(); err != nil {
					slog.Warn("signing key rotation", "error", err)
				}
			}
		}
	}()

	errc := make(chan error, 1)
	go func() {
		slog.Info("keston-id listening", "addr", cfg.Addr, "issuer", cfg.Issuer)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// Let in-flight requests finish while the load balancer moves on.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	slog.Info("shutting down")
	return srv.Shutdown(shutdownCtx)
}

// clientFile is one app in the JSON file `clients sync` reads. Secrets come
// from the environment variable named in secretEnv, never the file.
type clientFile struct {
	store.Client
	SecretEnv string `json:"secretEnv"`
}

func syncClients(ctx context.Context, st *store.Store, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var clients []clientFile
	if err := json.Unmarshal(data, &clients); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for _, c := range clients {
		if c.ID == "" || c.Name == "" || len(c.RedirectURIs) == 0 {
			return fmt.Errorf("client %q: id, name and redirectUris are required", c.ID)
		}
		if c.Verification == "" {
			c.Verification = "none"
		}
		for _, list := range []*[]string{&c.PostLogoutRedirectURIs, &c.RequiredScopes, &c.OptionalScopes} {
			if *list == nil {
				*list = []string{}
			}
		}
		var secretHash *string
		if c.SecretEnv != "" {
			value := os.Getenv(c.SecretEnv)
			if value == "" {
				return fmt.Errorf("client %q: %s is empty", c.ID, c.SecretEnv)
			}
			h := secret.HashPassword(value)
			secretHash = &h
		} else {
			public := ""
			secretHash = &public
		}
		if err := st.UpsertClient(ctx, &c.Client, secretHash); err != nil {
			return fmt.Errorf("client %q: %w", c.ID, err)
		}
		slog.Info("client synced", "id", c.ID, "public", c.SecretEnv == "")
	}
	return nil
}

func createUser(ctx context.Context, st *store.Store, args []string) error {
	fs := flag.NewFlagSet("users create", flag.ContinueOnError)
	email := fs.String("email", "", "sign-in email")
	name := fs.String("name", "", "full name")
	org := fs.String("organisation", "", "school or organisation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *name == "" {
		return errors.New("-email and -name are required")
	}
	password := os.Getenv("KESTON_ID_PASSWORD")
	if password == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	}
	if len([]rune(password)) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	u, err := st.CreateUser(ctx, *email, *name, *org, secret.HashPassword(password))
	if err != nil {
		return err
	}
	slog.Info("user created", "id", u.ID, "email", u.Email)
	return nil
}

// healthcheck asks this container's server if it's ready (database reachable).
func healthcheck() error {
	addr := os.Getenv("KESTON_ID_ADDR")
	if addr == "" {
		addr = ":4444"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://" + addr + "/readyz")
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %s", res.Status)
	}
	return nil
}
