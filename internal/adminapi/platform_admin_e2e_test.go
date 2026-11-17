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

// TKG Admin: separate from Global Admin, set by platform admins only, only in
// The Keston Group, never removed from oneself.
func TestTKGAdmin(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	platform, staff := e.platformAdmin()
	base := "/organisations/" + platform.ID

	newUser := func(role string, tkg bool) *store.User {
		name := "u" + secret.Hash(secret.Token())[:8]
		u, err := e.st.CreateUser(ctx, e.st.DB, store.NewUser{OrganisationID: platform.ID,
			Email: name + "@" + platform.Domain, Name: name, Role: role, PlatformAdmin: tkg,
			PasswordHash: secret.HashPassword("x")})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	// A global admin of The Keston Group isn't a platform admin by itself.
	plainAdmin := newUser("global_admin", false)
	if plainAdmin.PlatformAdmin {
		t.Fatal("a global admin of the platform organisation is a platform admin")
	}
	if code, _ := e.call(plainAdmin, http.MethodGet, "/platform-settings", nil); code != http.StatusForbidden {
		t.Errorf("global admin reads platform settings: %d", code)
	}

	// A platform admin makes them a TKG Admin; it's audited and in the JSON.
	code, raw := e.call(staff, http.MethodPatch, base+"/users/"+plainAdmin.ID, map[string]any{"platformAdmin": true})
	var got struct{ PlatformAdmin bool }
	_ = json.Unmarshal(raw, &got)
	if code != http.StatusOK || !got.PlatformAdmin {
		t.Fatalf("make TKG Admin: %d %s", code, raw)
	}
	if u, _ := e.st.UserByID(ctx, plainAdmin.ID); !u.PlatformAdmin {
		t.Error("not saved")
	}
	var logged int
	if err := e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2 AND summary LIKE '%TKG Admin%'`,
		store.ActionUserUpdated, plainAdmin.ID).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged == 0 {
		t.Error("the change isn't in the audit log")
	}

	// Needs global admin too.
	member := newUser("member", false)
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+member.ID, map[string]any{"platformAdmin": true}); code != http.StatusUnprocessableEntity {
		t.Errorf("TKG Admin for a member: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+member.ID,
		map[string]any{"role": "global_admin", "platformAdmin": true}); code != http.StatusOK {
		t.Errorf("TKG Admin with global admin: %d", code)
	}

	// Going back to a plain user takes TKG Admin away.
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+member.ID, map[string]any{"role": "member"}); code != http.StatusOK {
		t.Errorf("demote: %d", code)
	}
	if u, _ := e.st.UserByID(ctx, member.ID); u.PlatformAdmin || u.Role != "member" {
		t.Errorf("after demoting: %+v", u)
	}

	// Not on yourself.
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+staff.ID, map[string]any{"platformAdmin": false}); code != http.StatusUnprocessableEntity {
		t.Errorf("remove own: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+staff.ID, map[string]any{"role": "member"}); code != http.StatusUnprocessableEntity {
		t.Errorf("demote self: %d", code)
	}
	if u, _ := e.st.UserByID(ctx, staff.ID); !u.PlatformAdmin {
		t.Error("lost their own access")
	}

	// Another TKG Admin can be removed.
	if code, _ := e.call(staff, http.MethodPatch, base+"/users/"+plainAdmin.ID, map[string]any{"platformAdmin": false}); code != http.StatusOK {
		t.Errorf("remove another: %d", code)
	}

	// A global admin who isn't a TKG Admin can't make anyone one.
	if code, _ := e.call(plainAdmin, http.MethodPatch, base+"/users/"+member.ID,
		map[string]any{"role": "global_admin", "platformAdmin": true}); code != http.StatusUnprocessableEntity {
		t.Errorf("by a global admin: %d", code)
	}

	// Not outside The Keston Group.
	orgAdmin := e.admin()
	other := e.user("other", "global_admin")
	if code, _ := e.do(orgAdmin, http.MethodPatch, "/users/"+other.ID, map[string]any{"platformAdmin": true}); code != http.StatusUnprocessableEntity {
		t.Errorf("by an organisation's own admin: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPatch, "/organisations/"+e.org.ID+"/users/"+other.ID, map[string]any{"platformAdmin": true}); code != http.StatusUnprocessableEntity && code != http.StatusForbidden {
		t.Errorf("in another organisation: %d", code)
	}
	if u, _ := e.st.UserByID(ctx, other.ID); u.PlatformAdmin {
		t.Error("platform admin outside the platform organisation")
	}

	// Creating one.
	code, raw = e.call(staff, http.MethodPost, base+"/users", map[string]any{"name": "New Staff", "username": "ns" + secret.Hash(secret.Token())[:6],
		"generatePassword": true, "role": "global_admin", "platformAdmin": true})
	_ = json.Unmarshal(raw, &got)
	if code != http.StatusCreated || !got.PlatformAdmin {
		t.Errorf("create TKG Admin: %d %s", code, raw)
	}
}
