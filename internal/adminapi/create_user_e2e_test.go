//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// Adding a user with a password Keston ID makes up: it meets the policy, is
// returned once and works. Changing it at first sign-in is the admin's call,
// as for a typed one.
func TestCreateUserGeneratedPassword(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	code, raw := e.do(e.admin(), http.MethodPost, "/users", map[string]any{
		"name": "Gen Erated", "username": "gen", "generatePassword": true, "password": "ignored"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var out struct{ ID, Email, Password string }
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Password == "" || out.Password == "ignored" {
		t.Fatalf("password: got %q", out.Password)
	}
	if failed := e.org.PasswordPolicy.Check(out.Password, "gen"); len(failed) > 0 {
		t.Errorf("generated password fails the policy: %v", failed)
	}
	u, err := e.st.UserByID(ctx, out.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := secret.CheckPassword(u.PasswordHash, out.Password); !ok {
		t.Error("the returned password doesn't match the stored one")
	}
	st, err := e.st.SignInState(ctx, u, store.SignInContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.PasswordChangeRequired {
		t.Error("requirePasswordChange left out should default to on")
	}

	code, raw = e.do(e.admin(), http.MethodPost, "/users", map[string]any{
		"name": "Gen Kept", "username": "genkept", "generatePassword": true, "requirePasswordChange": false})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var kept struct{ ID string }
	_ = json.Unmarshal(raw, &kept)
	ku, _ := e.st.UserByID(ctx, kept.ID)
	if st, _ := e.st.SignInState(ctx, ku, store.SignInContext{}); st.PasswordChangeRequired {
		t.Error("requirePasswordChange: false should be respected for a generated password")
	}

	// Typed by the admin: not returned, and the change is up to them.
	code, raw = e.do(e.admin(), http.MethodPost, "/users", map[string]any{
		"name": "Typed In", "username": "typed", "password": "Correct-Horse-41-Battery",
		"requirePasswordChange": false})
	if code != http.StatusCreated {
		t.Fatalf("create typed: %d %s", code, raw)
	}
	var typed struct{ ID, Password string }
	_ = json.Unmarshal(raw, &typed)
	if typed.Password != "" {
		t.Error("a typed password shouldn't be returned")
	}
	tu, _ := e.st.UserByID(ctx, typed.ID)
	if st, _ := e.st.SignInState(ctx, tu, store.SignInContext{}); st.PasswordChangeRequired {
		t.Error("requirePasswordChange: false should be respected for a typed password")
	}
}
