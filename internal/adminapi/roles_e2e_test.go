//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

// Admin roles: given when adding a user or later, giving their permissions;
// only roles whose permissions you have yourself.
func TestAdminRoles(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()

	code, raw := e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "Hal Help", "username": "hal", "generatePassword": true, "roles": []string{"helpdesk_admin"}})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var hal struct{ ID string }
	_ = json.Unmarshal(raw, &hal)
	h, _ := e.st.UserByID(ctx, hal.ID)
	perms, _ := e.st.PermissionsOf(ctx, h)
	if !perms.Has(store.PermResetPassword) || perms.Has(store.PermDeleteUsers) {
		t.Errorf("helpdesk admin's permissions: %v", perms.List())
	}

	// Listed, with their roles.
	var list []struct {
		ID    string
		Roles []string
	}
	_, raw = e.do(admin, http.MethodGet, "/users", nil)
	_ = json.Unmarshal(raw, &list)
	for _, u := range list {
		if u.ID == hal.ID && (len(u.Roles) != 1 || u.Roles[0] != "helpdesk_admin") {
			t.Errorf("listed roles: %v", u.Roles)
		}
	}

	// An unknown role: refused, nobody added.
	if code, _ := e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "X", "username": "x", "generatePassword": true, "roles": []string{"overlord"}}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown role: %d", code)
	}

	// Someone with Give permissions but not every permission of User admin
	// can't give it, but can give Reports reader if they see logs.
	giver := e.user("giver", "member")
	g := e.group("Givers", store.PermAssign, store.PermReports, store.PermViewUsers)
	_ = e.st.AddGroupMember(ctx, g.ID, giver.ID)
	plain := e.user("plain", "member")
	if code, _ := e.do(giver, http.MethodPut, "/users/"+plain.ID+"/roles", map[string]any{"roles": []string{"user_admin"}}); code != http.StatusUnprocessableEntity {
		t.Errorf("giving a bigger role: %d", code)
	}
	if code, raw := e.do(giver, http.MethodPut, "/users/"+plain.ID+"/roles", map[string]any{"roles": []string{"reports_reader"}}); code != http.StatusOK {
		t.Errorf("giving reports reader: %d %s", code, raw)
	}
	if r, _ := e.st.RolesOf(ctx, plain.ID); len(r) != 1 {
		t.Errorf("plain's roles: %v", r)
	}

	// Taken away again by a global admin; audited.
	e.do(admin, http.MethodPut, "/users/"+plain.ID+"/roles", map[string]any{"roles": []string{}})
	if r, _ := e.st.RolesOf(ctx, plain.ID); len(r) != 0 {
		t.Errorf("after removing: %v", r)
	}
	var n int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2`,
		store.ActionUserRoles, plain.ID).Scan(&n)
	if n != 2 {
		t.Errorf("audit entries: %d", n)
	}
}
