//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

// A TKG Admin without support access sees and edits an organisation's licence
// allocations and its basic details, but not its dashboard; its own admins
// see the allocations read-only; people without permissions see nothing.
func TestBillingAccess(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	admin := e.admin()
	member := e.user("plain", "member")
	_, staff := e.platformAdmin()
	if staff.OrganisationID == e.org.ID {
		t.Fatal("staff should be in another organisation")
	}
	setSeats := func(as *store.User, seats any) int {
		code, _ := e.call(as, http.MethodPut, "/organisations/"+e.org.ID+"/licences",
			map[string]any{"allocations": []map[string]any{{"product": "work", "seats": seats}}})
		return code
	}
	work := func(as *store.User) (int, store.Product) {
		t.Helper()
		code, raw := e.do(as, http.MethodGet, "/products", nil)
		var list []store.Product
		if code == http.StatusOK {
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "@") {
				t.Errorf("products mention an email address: %s", raw)
			}
		}
		for _, p := range list {
			if p.ID == "work" {
				return code, p
			}
		}
		return code, store.Product{}
	}

	// Staff, without support access: read and edit allocations.
	if code := setSeats(staff, 4); code != http.StatusOK {
		t.Fatalf("staff set seats: %d", code)
	}
	if code, p := work(staff); code != http.StatusOK || p.Seats == nil || *p.Seats != 4 {
		t.Errorf("staff products: %d %+v", code, p)
	}
	if code := setSeats(staff, nil); code != http.StatusOK {
		t.Fatalf("staff set unlimited: %d", code)
	}
	if _, p := work(staff); !p.Unlimited {
		t.Errorf("want unlimited: %+v", p)
	}
	_ = setSeats(staff, 4)

	// The organisation's admin: sees allocations, can't edit.
	if code, p := work(admin); code != http.StatusOK || p.Seats == nil || *p.Seats != 4 {
		t.Errorf("admin products: %d %+v", code, p)
	}
	if code := setSeats(admin, 9); code != http.StatusForbidden {
		t.Errorf("admin set seats: %d, want 403", code)
	}
	if _, p := work(staff); p.Seats == nil || *p.Seats != 4 {
		t.Errorf("seats changed: %+v", p)
	}

	// Someone with no permissions: nothing.
	if code, _ := work(member); code != http.StatusNotFound {
		t.Errorf("member products: %d, want 404", code)
	}
	if code := setSeats(member, 9); code != http.StatusNotFound {
		t.Errorf("member set seats: %d, want 404", code)
	}
	// A group with only "Assign licences" can view them (read-only).
	g := e.group("Licensers", store.PermLicences)
	if err := e.st.AddGroupMember(ctx, g.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := work(member); code != http.StatusOK {
		t.Errorf("licences-permission products: %d, want 200", code)
	}
	if code := setSeats(member, 9); code != http.StatusForbidden {
		t.Errorf("licences-permission set seats: %d, want 403", code)
	}

	// Basic details for staff without support access.
	code, raw := e.do(staff, http.MethodGet, "/", nil)
	if code != http.StatusOK {
		t.Fatalf("staff details: %d %s", code, raw)
	}
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	if d["name"] != e.org.Name || d["domain"] != e.org.Domain || d["canManage"] != false {
		t.Errorf("details: %s", raw)
	}
	if ds, _ := d["domains"].([]any); len(ds) != 1 || ds[0] != e.org.Domain {
		t.Errorf("domains: %s", raw)
	}
	for _, k := range []string{"passwordPolicy", "profileEditing", "usernameFormat"} {
		if _, ok := d[k]; ok {
			t.Errorf("staff details include %q: %s", k, raw)
		}
	}
	// The organisation's admin gets the full record.
	code, raw = e.do(admin, http.MethodGet, "/", nil)
	d = nil
	_ = json.Unmarshal(raw, &d)
	if code != http.StatusOK || d["canManage"] != true || d["passwordPolicy"] == nil {
		t.Errorf("admin details: %d %s", code, raw)
	}

	// The dashboard's summary: refused for staff without support access,
	// available to the organisation's admin.
	if code, raw := e.do(staff, http.MethodGet, "/summary", nil); code != http.StatusForbidden || !strings.Contains(string(raw), "support_access") {
		t.Errorf("staff summary: %d %s", code, raw)
	}
	if code, _ := e.do(admin, http.MethodGet, "/summary", nil); code != http.StatusOK {
		t.Errorf("admin summary: %d", code)
	}
	// And the users and other data stay behind support access.
	if code, _ := e.do(staff, http.MethodGet, "/users", nil); code != http.StatusForbidden {
		t.Errorf("staff users: %d, want 403", code)
	}
}
