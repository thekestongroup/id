//go:build e2e

package adminapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestProfilesE2E(t *testing.T) {
	e := setup(t)
	admin := e.admin()
	a, b, c := e.user("ann", "member"), e.user("ben", "member"), e.user("cat", "member")

	// Attribute definitions.
	code, raw := e.do(admin, http.MethodPost, "/user-attributes", map[string]any{"key": "house", "label": "House", "type": "choice", "choices": []string{"Red", "Blue"}})
	if code != http.StatusCreated {
		t.Fatalf("create attr: %d %s", code, raw)
	}
	if code, _ = e.do(admin, http.MethodPost, "/user-attributes", map[string]any{"key": "house", "label": "Again", "type": "text"}); code != 422 {
		t.Errorf("duplicate key: %d", code)
	}
	if code, _ = e.do(admin, http.MethodPost, "/user-attributes", map[string]any{"key": "department", "label": "X", "type": "text"}); code != 422 {
		t.Errorf("reserved key: %d", code)
	}

	put := func(u string, body map[string]any) (int, []byte) {
		return e.do(admin, http.MethodPut, "/users/"+u+"/profile", body)
	}
	if code, raw = put(a.ID, map[string]any{"department": "Science", "phone": "+44 20 7123 4567", "attributes": map[string]any{"house": "red"}}); code != 200 {
		t.Fatalf("put: %d %s", code, raw)
	}
	var got struct {
		Phone      string
		Attributes map[string]any
	}
	_ = json.Unmarshal(raw, &got)
	if got.Phone != "+442071234567" || got.Attributes["house"] != "Red" {
		t.Errorf("got %+v", got)
	}
	if code, _ = put(a.ID, map[string]any{"phone": "020 7123"}); code != 422 {
		t.Errorf("bad phone: %d", code)
	}
	if code, _ = put(a.ID, map[string]any{"attributes": map[string]any{"house": "Green"}}); code != 422 {
		t.Errorf("bad choice: %d", code)
	}

	// Managers: a ← b ← c; a can't report to c or to themselves.
	if code, raw = put(b.ID, map[string]any{"managerId": a.ID}); code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	if code, raw = put(c.ID, map[string]any{"managerId": b.ID}); code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	if code, _ = put(a.ID, map[string]any{"managerId": c.ID}); code != 422 {
		t.Errorf("cycle accepted: %d", code)
	}
	if code, _ = put(a.ID, map[string]any{"managerId": a.ID}); code != 422 {
		t.Errorf("self-manager accepted: %d", code)
	}
	if code, _ = put(a.ID, map[string]any{"managerId": "00000000-0000-0000-0000-000000000000"}); code != 422 {
		t.Errorf("unknown manager accepted: %d", code)
	}

	// Direct reports on the user, and filtering the list.
	code, raw = e.do(admin, http.MethodGet, "/users/"+a.ID, nil)
	var u struct{ Reports []personRef }
	_ = json.Unmarshal(raw, &u)
	if code != 200 || len(u.Reports) != 1 || u.Reports[0].ID != b.ID {
		t.Errorf("reports: %d %s", code, raw)
	}
	code, raw = e.do(admin, http.MethodGet, "/users?department=science&attr.house=red", nil)
	var rows []userRow
	_ = json.Unmarshal(raw, &rows)
	if code != 200 || len(rows) != 1 || rows[0].ID != a.ID {
		t.Errorf("filter: %d %s", code, raw)
	}

	// Bulk create with a manager by username and attributes.
	code, raw = e.do(admin, http.MethodPost, "/users/bulk/create", map[string]any{"users": []map[string]any{
		{"name": "Dan", "username": "dan", "profile": map[string]any{"jobTitle": "Teacher", "managerEmail": "ann", "attributes": map[string]any{"house": "Blue"}}},
		{"name": "Eve", "username": "eve", "profile": map[string]any{"managerEmail": "nobody"}},
	}})
	if code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	var res struct{ Results []bulkResult }
	_ = json.Unmarshal(raw, &res)
	if res.Results[0].Result != "done" || res.Results[1].Result != "skipped" {
		t.Errorf("bulk: %s", raw)
	}
	// Deleting an attribute removes it.
	var def struct{ ID string }
	_, raw = e.do(admin, http.MethodGet, "/user-attributes", nil)
	var defs []struct{ ID string }
	_ = json.Unmarshal(raw, &defs)
	def = defs[0]
	if code, _ = e.do(admin, http.MethodDelete, "/user-attributes/"+def.ID, nil); code != 204 {
		t.Errorf("delete: %d", code)
	}
}
