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

// Licence allocations: seats per product per organisation, set by TKG
// Admins, enforced when assigning (one, in bulk, adding users).
func TestLicenceSeats(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	admin := e.admin()
	_, staff := e.platformAdmin()

	work := func() store.Product {
		t.Helper()
		code, raw := e.do(admin, http.MethodGet, "/products", nil)
		var list []store.Product
		if code != http.StatusOK || json.Unmarshal(raw, &list) != nil {
			t.Fatalf("products: %d %s", code, raw)
		}
		for _, p := range list {
			if p.ID == "work" {
				return p
			}
		}
		t.Fatal("no work product")
		return store.Product{}
	}
	setSeats := func(as *store.User, seats any) (int, []byte) {
		return e.call(as, http.MethodPut, "/organisations/"+e.org.ID+"/licences",
			map[string]any{"allocations": []map[string]any{{"product": "work", "seats": seats}}})
	}
	assign := func(u *store.User, products ...string) (int, []byte) {
		return e.do(admin, http.MethodPut, "/users/"+u.ID+"/licences", map[string]any{"products": products})
	}

	// Unlimited to begin with.
	p := work()
	if !p.Unlimited || p.Seats != nil || p.Available != nil || p.OverAllocated {
		t.Fatalf("default: %+v", p)
	}
	used := p.Assigned

	// Only TKG Admins set them.
	if code, _ := setSeats(admin, used+2); code != http.StatusForbidden {
		t.Errorf("global admin sets seats: %d", code)
	}
	if code, raw := setSeats(staff, -1); code != http.StatusUnprocessableEntity {
		t.Errorf("negative seats: %d %s", code, raw)
	}
	code, raw := setSeats(staff, used+2)
	if code != http.StatusOK {
		t.Fatalf("set seats: %d %s", code, raw)
	}
	p = work()
	if p.Unlimited || *p.Seats != used+2 || *p.Available != 2 || p.OverAllocated {
		t.Fatalf("after setting: %+v", p)
	}
	var logged int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND organisation_id = $2
		AND summary LIKE '%Keston Work%unlimited →%'`, store.ActionOrgLicences, e.org.ID).Scan(&logged)
	if logged != 1 {
		t.Errorf("audit entries: %d", logged)
	}

	// Single assignment: two fit, the third fails clearly and changes nothing.
	u1, u2, u3, u4, u5 := e.user("u1", "member"), e.user("u2", "member"), e.user("u3", "member"),
		e.user("u4", "member"), e.user("u5", "member")
	for _, u := range []*store.User{u1, u2} {
		if code, raw := assign(u, "work"); code != http.StatusOK {
			t.Fatalf("assign %s: %d %s", u.Name, code, raw)
		}
	}
	code, raw = assign(u3, "work")
	if code != http.StatusConflict || !strings.Contains(string(raw), "no_licences_left") ||
		!strings.Contains(string(raw), "Keston Work") {
		t.Errorf("full: %d %s", code, raw)
	}
	if l, _ := e.st.Licences(ctx, u3.ID); len(l) != 0 {
		t.Errorf("u3 got %v", l)
	}
	if p = work(); *p.Available != 0 || p.OverAllocated {
		t.Errorf("full: %+v", p)
	}
	// Assigning what they already have is fine even when full.
	if code, _ := assign(u1, "work"); code != http.StatusOK {
		t.Errorf("reassign: %d", code)
	}

	// Adding a user with a licence: refused, and nobody is created.
	code, raw = e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "New", "username": "newbie", "generatePassword": true, "licences": []string{"work"}})
	if code != http.StatusConflict {
		t.Errorf("add user when full: %d %s", code, raw)
	}
	if _, err := e.st.UserByEmail(ctx, "newbie@"+e.org.Domain); err == nil {
		t.Error("a user was created despite no licences left")
	}
	// Without a licence they can still be added.
	if code, raw = e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "New", "username": "newbie", "generatePassword": true}); code != http.StatusCreated {
		t.Errorf("add without licence: %d %s", code, raw)
	}

	// Bulk create with licences when full: all skipped; with one seat free:
	// the first is added, the rest skipped.
	bulkCreate := func() []bulkResult {
		code, raw := e.do(admin, http.MethodPost, "/users/bulk/create", map[string]any{
			"users":    []map[string]string{{"name": "A B", "username": "bulka"}, {"name": "C D", "username": "bulkb"}},
			"licences": []string{"work"}, "password": "Correct-Horse-Battery-9!"})
		if code != http.StatusOK {
			t.Fatalf("bulk create: %d %s", code, raw)
		}
		var out struct{ Results []bulkResult }
		_ = json.Unmarshal(raw, &out)
		return out.Results
	}
	for _, r := range bulkCreate() {
		if r.Result != "skipped" || !strings.Contains(r.Reason, "licences left") {
			t.Errorf("bulk create when full: %+v", r)
		}
	}

	// Free a seat; bulk assigning to three leaves the first done, the rest skipped.
	if code, _ := assign(u1); code != http.StatusOK {
		t.Fatal("remove")
	}
	res := e.bulk(admin, "/users/bulk/licences", map[string]any{"userIds": ids(u3, u4, u5), "add": []string{"work"}})
	expect(t, res, u3, "done", "")
	expect(t, res, u4, "skipped", "Keston Work licences left")
	expect(t, res, u5, "skipped", "Keston Work licences left")
	// Taking away always works, and frees seats for the next bulk.
	res = e.bulk(admin, "/users/bulk/licences", map[string]any{"userIds": ids(u2, u3), "remove": []string{"work"}})
	expect(t, res, u2, "done", "")
	expect(t, res, u3, "done", "")
	for _, r := range bulkCreate() {
		if r.Result != "done" {
			t.Errorf("bulk create with seats: %+v", r)
		}
	}
	if p = work(); *p.Available != 0 {
		t.Errorf("after bulk create: %+v", p)
	}

	// Reducing seats below use is allowed: over allocation, nothing new,
	// removing still fine, and assigning again once under.
	if code, raw := setSeats(staff, 0); code != http.StatusOK {
		t.Fatalf("reduce: %d %s", code, raw)
	}
	p = work()
	if !p.OverAllocated || *p.Available != 0 || p.Assigned < 2 {
		t.Fatalf("over allocation: %+v", p)
	}
	code, raw = assign(u4, "work")
	if code != http.StatusConflict || !strings.Contains(string(raw), "over its allocation") {
		t.Errorf("assign while over: %d %s", code, raw)
	}
	if l, _ := e.st.Licences(ctx, u1.ID); len(l) != 0 {
		t.Error("u1 unexpectedly licensed")
	}
	setSeats(staff, p.Assigned) // exactly full: not over, but still no room
	if p = work(); p.OverAllocated || *p.Available != 0 {
		t.Errorf("full: %+v", p)
	}
	if code, _ := assign(u4, "work"); code != http.StatusConflict {
		t.Errorf("assign when full again: %d", code)
	}
	setSeats(staff, p.Assigned+1)
	if code, raw := assign(u4, "work"); code != http.StatusOK {
		t.Errorf("assign once under: %d %s", code, raw)
	}

	// Unlimited again: nothing stops it.
	if code, raw := setSeats(staff, nil); code != http.StatusOK {
		t.Fatalf("unlimited: %d %s", code, raw)
	}
	for _, u := range []*store.User{u1, u2, u3, u5} {
		if code, raw := assign(u, "work"); code != http.StatusOK {
			t.Errorf("unlimited assign: %d %s", code, raw)
		}
	}
	if p = work(); !p.Unlimited || p.Available != nil {
		t.Errorf("unlimited: %+v", p)
	}

	// Unknown product.
	code, _ = e.call(staff, http.MethodPut, "/organisations/"+e.org.ID+"/licences",
		map[string]any{"allocations": []map[string]any{{"product": "nope", "seats": 1}}})
	if code != http.StatusUnprocessableEntity {
		t.Errorf("unknown product: %d", code)
	}
}
