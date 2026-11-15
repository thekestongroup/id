//go:build e2e

// End-to-end tests for passkeys in Keston Admin, against a real Postgres:
//
//	KESTON_ID_TEST_DATABASE_URL=postgres://keston:keston@localhost:55430/keston_id?sslmode=disable \
//		go test -tags e2e ./internal/...
package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

func TestAdminPasskeys(t *testing.T) {
	dsn := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("KESTON_ID_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	box, _ := secret.NewBox([32]byte{4})
	st := store.New(pool, box)
	suffix := fmt.Sprint(time.Now().UnixNano())
	domain := "adm" + suffix + ".test"
	org, admin, err := st.CreateOrganisation(ctx, "Admin Passkeys "+suffix, domain, store.NewUser{
		Email: "admin@" + domain, Name: "Admin", Role: "global_admin", PasswordHash: secret.HashPassword("x")})
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, st.DB, store.NewUser{OrganisationID: org.ID, Email: "sam@" + domain, Name: "Sam",
		PasswordHash: secret.HashPassword("x")})
	if err != nil {
		t.Fatal(err)
	}
	addKey := func(name string) {
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		if _, err := st.AddPasskey(ctx, user.ID, name, &webauthn.Credential{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	addKey("Phone")
	addKey("YubiKey")

	a := New(st, nil, "http://id.keston.localhost:4444")
	call := func(h http.HandlerFunc, method string) (int, map[string]any) {
		req := httptest.NewRequest(method, "/", nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("userID", user.ID)
		c := context.WithValue(req.Context(), chi.RouteCtxKey, rc)
		c = context.WithValue(c, userKey, admin)
		c = context.WithValue(c, permsKey, store.Perms{store.PermViewUsers: true, store.PermResetMFA: true})
		c = context.WithValue(c, orgKey, org)
		w := httptest.NewRecorder()
		h(w, req.WithContext(c))
		out := map[string]any{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// The user page shows the count, and MFA on (passkeys only, no app).
	code, out := call(a.getUser, "GET")
	if code != 200 || out["passkeys"] != float64(2) || out["mfa"] != true {
		t.Fatalf("getUser %d %v", code, out)
	}
	// So does the list.
	req := httptest.NewRequest("GET", "/", nil)
	c := context.WithValue(req.Context(), userKey, admin)
	c = context.WithValue(c, permsKey, store.Perms{store.PermViewUsers: true})
	c = context.WithValue(c, orgKey, org)
	w := httptest.NewRecorder()
	a.listUsers(w, req.WithContext(c))
	var rows []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &rows)
	for _, r := range rows {
		want := 0.0
		if r["id"] == user.ID {
			want = 2
		}
		if r["passkeys"] != want {
			t.Fatalf("list row %v", r)
		}
	}

	// Remove the passkeys: MFA is off.
	code, out = call(a.removePasskeys, "DELETE")
	if code != 200 || out["passkeys"] != float64(0) || out["mfa"] != false {
		t.Fatalf("removePasskeys %d %v", code, out)
	}
	if code, _ = call(a.removePasskeys, "DELETE"); code != 409 {
		t.Fatalf("removing none: %d", code)
	}

	// Turning off MFA removes passkeys too, and works for passkeys alone.
	addKey("Phone")
	code, out = call(a.disableMFA, "POST")
	if code != 200 || out["passkeys"] != float64(0) || out["mfa"] != false {
		t.Fatalf("disableMFA %d %v", code, out)
	}
	if code, _ = call(a.disableMFA, "POST"); code != 409 {
		t.Fatalf("disableMFA when off: %d", code)
	}
}
