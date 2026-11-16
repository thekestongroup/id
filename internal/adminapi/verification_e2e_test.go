//go:build e2e

package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// platformAdmin: a global admin of The Keston Group's organisation.
func (e *env) platformAdmin() (*store.Organisation, *store.User) {
	e.t.Helper()
	ctx := context.Background()
	var id string
	if err := e.st.DB.QueryRow(ctx, `SELECT id FROM organisations WHERE is_platform`).Scan(&id); err != nil {
		if _, err := e.st.EnsurePlatformOrganisation(ctx, "The Keston Group", "tkg"+secret.Hash(secret.Token())[:6]+".test"); err != nil {
			e.t.Fatal(err)
		}
		_ = e.st.DB.QueryRow(ctx, `SELECT id FROM organisations WHERE is_platform`).Scan(&id)
	}
	org, err := e.st.OrganisationByID(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	name := "staff" + secret.Hash(secret.Token())[:6]
	u, err := e.st.CreateUser(ctx, e.st.DB, store.NewUser{OrganisationID: org.ID, Email: name + "@" + org.Domain,
		Name: name, Role: "global_admin", PasswordHash: secret.HashPassword("x")})
	if err != nil {
		e.t.Fatal(err)
	}
	if !u.PlatformAdmin {
		e.t.Fatal("not a platform admin")
	}
	return org, u
}

// call: an API request (no organisation in the path) as this user.
func (e *env) call(as *store.User, method, path string, body any) (int, []byte) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+e.token(as))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *env) signUp(domain string) (int, struct {
	Organisation         store.Organisation
	AwaitingVerification bool
}) {
	e.t.Helper()
	body, _ := json.Marshal(map[string]string{"name": "New " + domain, "domain": domain, "adminName": "Ann Admin",
		"adminUsername": "ann", "adminPassword": "correct horse battery staple"})
	req := httptest.NewRequest(http.MethodPost, "/organisations", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	e.api.PublicRoutes().ServeHTTP(rec, req)
	var out struct {
		Organisation         store.Organisation
		AwaitingVerification bool
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestPlatformSettingAndVerification(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	platform, staff := e.platformAdmin()
	orgAdmin := e.admin()
	t.Cleanup(func() { _ = e.st.SetRequireOrganisationVerification(ctx, false) })
	_ = e.st.SetRequireOrganisationVerification(ctx, false)

	// The setting: platform admins only, default off.
	if code, _ := e.call(orgAdmin, http.MethodGet, "/platform-settings", nil); code != http.StatusForbidden {
		t.Errorf("org admin reads the setting: %d", code)
	}
	if code, _ := e.call(orgAdmin, http.MethodPut, "/platform-settings",
		map[string]bool{"requireOrganisationVerification": true}); code != http.StatusForbidden {
		t.Errorf("org admin changes the setting: %d", code)
	}
	if on, _ := e.st.RequireOrganisationVerification(ctx); on {
		t.Fatal("an org admin turned the setting on")
	}
	var s struct{ RequireOrganisationVerification bool }
	code, raw := e.call(staff, http.MethodGet, "/platform-settings", nil)
	_ = json.Unmarshal(raw, &s)
	if code != http.StatusOK || s.RequireOrganisationVerification {
		t.Fatalf("default: %d %s", code, raw)
	}

	// Off: public sign-up is verified at once.
	code, out := e.signUp("off" + secret.Hash(secret.Token())[:8] + ".test")
	if code != http.StatusCreated || !out.Organisation.Verified || out.AwaitingVerification {
		t.Fatalf("sign-up with the setting off: %d %+v", code, out)
	}

	// On: public sign-up is unverified, and the response says so.
	if code, raw := e.call(staff, http.MethodPut, "/platform-settings",
		map[string]bool{"requireOrganisationVerification": true}); code != http.StatusOK {
		t.Fatalf("turn on: %d %s", code, raw)
	}
	code, out = e.signUp("on" + secret.Hash(secret.Token())[:8] + ".test")
	if code != http.StatusCreated || out.Organisation.Verified || !out.AwaitingVerification {
		t.Fatalf("sign-up with the setting on: %d %+v", code, out)
	}
	waiting := out.Organisation
	if u, _ := e.st.UserByEmail(ctx, "ann@"+waiting.Domain); u == nil || u.Usable() {
		t.Error("the first admin of an unverified organisation can sign in")
	}

	// Organisations made by platform admins are always verified.
	d := "made" + secret.Hash(secret.Token())[:8] + ".test"
	code, raw = e.call(staff, http.MethodPost, "/organisations", map[string]string{"name": "Made", "domain": d,
		"adminName": "Bo Admin", "adminUsername": "bo", "adminPassword": "correct horse battery staple"})
	var made struct{ Organisation store.Organisation }
	_ = json.Unmarshal(raw, &made)
	if code != http.StatusCreated || !made.Organisation.Verified {
		t.Fatalf("created by a platform admin: %d %s", code, raw)
	}

	// Verifying: platform admins only; once; recorded in the audit log.
	if code, _ := e.call(orgAdmin, http.MethodPost, "/organisations/"+waiting.ID+"/verify", nil); code != http.StatusNotFound &&
		code != http.StatusForbidden {
		t.Errorf("another organisation's admin verifies: %d", code)
	}
	selfCode, _ := e.call(orgAdmin, http.MethodPost, "/organisations/"+e.org.ID+"/verify", nil)
	if selfCode != http.StatusForbidden {
		t.Errorf("an organisation's own admin verifies it: %d", selfCode)
	}
	code, raw = e.call(staff, http.MethodPost, "/organisations/"+waiting.ID+"/verify", nil)
	var verified store.Organisation
	_ = json.Unmarshal(raw, &verified)
	if code != http.StatusOK || !verified.Verified {
		t.Fatalf("verify: %d %s", code, raw)
	}
	if u, _ := e.st.UserByEmail(ctx, "ann@"+waiting.Domain); u == nil || !u.Usable() {
		t.Error("people can't sign in once verified")
	}
	if code, _ := e.call(staff, http.MethodPost, "/organisations/"+waiting.ID+"/verify", nil); code != http.StatusConflict {
		t.Errorf("verify twice: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPost, "/organisations/"+platform.ID+"/verify", nil); code != http.StatusConflict {
		t.Errorf("verify the platform organisation: %d", code)
	}
	var n int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action = $2
		AND actor_id = $3`, waiting.ID, store.ActionOrganisationVerified, staff.ID).Scan(&n)
	if n != 1 {
		t.Errorf("audit entries for verifying: %d", n)
	}

	// Listed unverified organisations come first (after the platform one).
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET verified_at = NULL, verified_by = NULL WHERE id = $1`,
		waiting.ID); err != nil {
		t.Fatal(err)
	}
	_, raw = e.call(staff, http.MethodGet, "/organisations", nil)
	var list []store.Organisation
	_ = json.Unmarshal(raw, &list)
	if len(list) < 3 || !list[0].IsPlatform || list[1].Verified {
		t.Errorf("order: %+v", list[:min(3, len(list))])
	}
}
