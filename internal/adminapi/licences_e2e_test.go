//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

func TestLicences(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	admin := e.admin()

	// Added with a licence; without one, Keston Work is off for them.
	code, raw := e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "Lee Licensed", "username": "lee", "generatePassword": true, "licences": []string{"work"}})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var lee struct{ ID string }
	_ = json.Unmarshal(raw, &lee)
	code, raw = e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "Nina None", "username": "nina", "generatePassword": true})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var nina struct{ ID string }
	_ = json.Unmarshal(raw, &nina)

	effective := func(id string) string {
		u, err := e.st.UserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		eff, err := e.st.EffectiveApps(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		return eff["work"]
	}
	if got := effective(lee.ID); got != store.AppForced {
		t.Errorf("licensed: got %q, want forced", got)
	}
	if got := effective(nina.ID); got != store.AppDisabled {
		t.Errorf("unlicensed: got %q, want disabled", got)
	}

	// An unknown product: rejected, and nobody is created.
	code, _ = e.do(admin, http.MethodPost, "/users", map[string]any{
		"name": "Bad", "username": "bad", "generatePassword": true, "licences": []string{"nope"}})
	if code != http.StatusUnprocessableEntity {
		t.Errorf("unknown product: got %d", code)
	}
	if _, err := e.st.UserByEmail(ctx, "bad@"+e.org.Domain); err == nil {
		t.Error("a user was created despite the bad licence")
	}

	// Given one later, and taken away.
	code, raw = e.do(admin, http.MethodPut, "/users/"+nina.ID+"/licences", map[string]any{"products": []string{"work"}})
	if code != http.StatusOK || effective(nina.ID) != store.AppForced {
		t.Errorf("assign: %d %s, now %q", code, raw, effective(nina.ID))
	}
	code, _ = e.do(admin, http.MethodPut, "/users/"+nina.ID+"/licences", map[string]any{"products": []string{}})
	if code != http.StatusOK || effective(nina.ID) != store.AppDisabled {
		t.Errorf("remove: %d, now %q", code, effective(nina.ID))
	}

	// Shown on the list, the user and the product count.
	var list []struct {
		ID       string
		Licences []string
	}
	_, raw = e.do(admin, http.MethodGet, "/users", nil)
	_ = json.Unmarshal(raw, &list)
	for _, u := range list {
		if u.ID == lee.ID && !slices.Contains(u.Licences, "work") {
			t.Errorf("list: Lee's licences %v", u.Licences)
		}
		if u.ID == nina.ID && len(u.Licences) != 0 {
			t.Errorf("list: Nina's licences %v", u.Licences)
		}
	}
	var products []store.Product
	_, raw = e.do(admin, http.MethodGet, "/products", nil)
	_ = json.Unmarshal(raw, &products)
	// Keston Work: Lee (and the first admin, if Keston Work existed when the
	// organisation was set up).
	var want int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM user_licences l JOIN users u ON u.id = l.user_id
		WHERE l.client_id = 'work' AND u.organisation_id = $1`, e.org.ID).Scan(&want)
	i := slices.IndexFunc(products, func(p store.Product) bool { return p.ID == "work" })
	if i < 0 || want < 1 || products[i].Assigned != want {
		t.Errorf("products: %s, want %d for work", raw, want)
	}

	// Without "Assign licences": can add users, but not with licences.
	helper := e.user("helper", "member")
	g := e.group("Helpdesk", store.PermCreateUsers)
	if err := e.st.AddGroupMember(ctx, g.ID, helper.ID); err != nil {
		t.Fatal(err)
	}
	code, _ = e.do(helper, http.MethodPost, "/users", map[string]any{
		"name": "Sam", "username": "sam", "generatePassword": true, "licences": []string{"work"}})
	if code != http.StatusUnprocessableEntity {
		t.Errorf("licences without the permission: got %d", code)
	}
	code, _ = e.do(helper, http.MethodPut, "/users/"+lee.ID+"/licences", map[string]any{"products": []string{}})
	if code != http.StatusForbidden {
		t.Errorf("PUT licences without the permission: got %d", code)
	}

	// Their apps: Keston Work on for Lee, kept from Nina for want of a licence.
	appAccess := func(id string) string {
		var apps []struct{ ID, Access string }
		_, raw := e.do(admin, http.MethodGet, "/users/"+id+"/apps", nil)
		_ = json.Unmarshal(raw, &apps)
		for _, a := range apps {
			if a.ID == "work" {
				return a.Access
			}
		}
		return ""
	}
	if got := appAccess(lee.ID); got != store.AppForced {
		t.Errorf("Lee's Keston Work: %q", got)
	}
	if got := appAccess(nina.ID); got != "no_licence" {
		t.Errorf("Nina's Keston Work: %q", got)
	}

	// Audited.
	var n int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2`,
		store.ActionUserLicences, nina.ID).Scan(&n)
	if n != 2 {
		t.Errorf("audit entries for Nina: %d, want 2", n)
	}
}
