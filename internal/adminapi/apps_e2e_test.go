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

type ruleOut struct {
	ID, Name, Mode string
	Enabled        bool
}

func addApp(t *testing.T, e *env, id string) {
	t.Helper()
	if _, err := e.st.DB.Exec(context.Background(), `INSERT INTO clients (id, name, publisher, redirect_uris)
		VALUES ($1, $1, 'Someone Else', '{}') ON CONFLICT DO NOTHING`, id); err != nil {
		t.Fatal(err)
	}
}

// App access: the organisation's default per app, and ordered rules that
// override it (users, groups, IP addresses): first match wins.
func TestAppRules(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	app := "app" + secret.Hash(secret.Token())[:8]
	addApp(t, e, app)
	base := "/apps/" + app

	ann, bob := e.user("ann", "member"), e.user("bob", "member")
	teachers := e.group("Teachers")
	office := e.group("Office")
	if err := e.st.AddGroupMember(ctx, teachers.ID, ann.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddGroupMember(ctx, office.ID, ann.ID); err != nil {
		t.Fatal(err)
	}
	access := func(u *store.User, ip string) string {
		eff, err := e.st.EffectiveAppsFrom(ctx, u, ip)
		if err != nil {
			t.Fatal(err)
		}
		return eff[app]
	}
	if got := access(ann, ""); got != "" {
		t.Fatalf("no setting: %q", got)
	}

	// The default.
	if code, raw := e.do(admin, http.MethodPut, base, map[string]any{"mode": "enabled"}); code != http.StatusNoContent {
		t.Fatalf("default: %d %s", code, raw)
	}
	if got := access(bob, ""); got != store.AppEnabled {
		t.Errorf("default: %q", got)
	}
	// Per-group settings are rules now.
	if code, _ := e.do(admin, http.MethodPut, base, map[string]any{"mode": "forced", "groupId": teachers.ID}); code != http.StatusUnprocessableEntity {
		t.Errorf("group setting through the default: %d", code)
	}

	save := func(path, method string, body map[string]any) (int, ruleOut) {
		code, raw := e.do(admin, method, base+path, body)
		var out ruleOut
		_ = json.Unmarshal(raw, &out)
		return code, out
	}
	code, forced := save("/rules", http.MethodPost, map[string]any{"name": "Office", "mode": "forced", "groups": []string{office.ID}})
	if code != http.StatusCreated {
		t.Fatalf("add rule: %d", code)
	}
	code, disabled := save("/rules", http.MethodPost, map[string]any{"name": "Teachers", "mode": "disabled", "groups": []string{teachers.ID}})
	if code != http.StatusCreated {
		t.Fatalf("add rule: %d", code)
	}
	// Ann is in both: the first rule (Forced) decides; bob matches neither.
	if got := access(ann, ""); got != store.AppForced {
		t.Errorf("first match: %q", got)
	}
	if got := access(bob, ""); got != store.AppEnabled {
		t.Errorf("no match: %q", got)
	}

	// Reorder: Disabled first, as the old per-group precedence had it.
	code, raw := e.do(admin, http.MethodPut, base+"/rules/order", map[string]any{"ids": []string{disabled.ID, forced.ID}})
	if code != http.StatusOK {
		t.Fatalf("order: %d %s", code, raw)
	}
	if got := access(ann, ""); got != store.AppDisabled {
		t.Errorf("after reorder: %q", got)
	}
	if code, _ := e.do(admin, http.MethodPut, base+"/rules/order", map[string]any{"ids": []string{disabled.ID}}); code != http.StatusBadRequest {
		t.Errorf("order missing a rule: %d", code)
	}

	// Turned off: skipped.
	if code, _ := save("/rules/"+disabled.ID, http.MethodPut, map[string]any{"name": "Teachers", "mode": "disabled",
		"enabled": false, "groups": []string{teachers.ID}}); code != http.StatusOK {
		t.Fatalf("turn off: %d", code)
	}
	if got := access(ann, ""); got != store.AppForced {
		t.Errorf("turned off rule: %q", got)
	}

	// By address: only matches when the address is known and in range.
	if code, _ := save("/rules", http.MethodPost, map[string]any{"name": "Office network", "mode": "disabled",
		"users": []string{bob.ID}, "ipRanges": []string{"10.0.0.0/8"}}); code != http.StatusCreated {
		t.Fatalf("ip rule: %d", code)
	}
	if got := access(bob, "10.2.3.4"); got != store.AppDisabled {
		t.Errorf("in range: %q", got)
	}
	if got := access(bob, "192.0.2.1"); got != store.AppEnabled {
		t.Errorf("out of range: %q", got)
	}
	if got := access(bob, ""); got != store.AppEnabled {
		t.Errorf("unknown address: %q", got)
	}

	// Checked: names, modes, whose they are, addresses.
	for name, body := range map[string]map[string]any{
		"no name":      {"mode": "forced"},
		"bad mode":     {"name": "x", "mode": "maybe"},
		"other group":  {"name": "x", "mode": "forced", "groups": []string{"00000000-0000-0000-0000-000000000000"}},
		"bad address":  {"name": "x", "mode": "forced", "ipRanges": []string{"not-an-ip"}},
		"unknown user": {"name": "x", "mode": "forced", "users": []string{"00000000-0000-0000-0000-000000000000"}},
	} {
		if code, _ := save("/rules", http.MethodPost, body); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", name, code)
		}
	}
	// Someone without "Set app access" can't.
	if code, _ := e.do(bob, http.MethodGet, base+"/rules", nil); code == http.StatusOK {
		t.Errorf("member lists rules: %d", code)
	}

	// Deleting a group takes it out of rules; a rule only about it goes too
	// (it would otherwise apply to everyone).
	if err := e.st.DeleteGroup(ctx, e.org.ID, office.ID); err != nil {
		t.Fatal(err)
	}
	rules, err := e.st.AppRules(ctx, e.org.ID, app)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == forced.ID {
			t.Errorf("rule about a deleted group is still there: %+v", r)
		}
	}
	if got := access(bob, ""); got != store.AppEnabled {
		t.Errorf("after deleting the group: %q", got)
	}

	// Deleting a rule; and it's all in the audit log.
	if code, _ := e.do(admin, http.MethodDelete, base+"/rules/"+disabled.ID, nil); code != http.StatusNoContent {
		t.Errorf("delete: %d", code)
	}
	if code, _ := e.do(admin, http.MethodDelete, base+"/rules/"+disabled.ID, nil); code != http.StatusNotFound {
		t.Errorf("delete again: %d", code)
	}
	var audited int
	if err := e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action = $2
		AND target_id = $3`, e.org.ID, store.ActionAppAccess, app).Scan(&audited); err != nil || audited < 5 {
		t.Errorf("audited %d changes: %v", audited, err)
	}
}

// Keston-wide apps: only TKG Admins in The Keston Group manage them; the
// secret is shown once and kept hashed; clients sync leaves them alone; a
// retired one isn't available.
func TestKestonApps(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	platform, staff := e.platformAdmin()
	base := "/organisations/" + platform.ID + "/keston-apps"

	// Not for an ordinary organisation's admin.
	if code, _ := e.do(e.admin(), http.MethodGet, "/keston-apps", nil); code != http.StatusForbidden {
		t.Errorf("other organisation's admin: %d", code)
	}

	code, raw := e.call(staff, http.MethodPost, base, map[string]any{"name": "Keston Quiz", "type": "web",
		"description": "Quizzes", "redirectUris": []string{"https://quiz.example.com/callback"}, "scopes": []string{"profile", "email"}})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	var created struct {
		App          kestonAppJSON
		ClientSecret string
	}
	_ = json.Unmarshal(raw, &created)
	id := created.App.ID
	if created.ClientSecret == "" || !created.App.HasSecret || created.App.ManagedBy != "admin" || created.App.Publisher != store.KestonPublisher {
		t.Fatalf("created: %+v", created)
	}
	c, err := e.st.ClientByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretHash == nil || *c.SecretHash == created.ClientSecret {
		t.Error("the secret is stored in plain text")
	}
	if ok, _ := secret.CheckPassword(*c.SecretHash, created.ClientSecret); !ok {
		t.Error("the secret shown doesn't match the hash")
	}
	if c.Verification != "none" || c.Builtin || c.OrganisationID != nil {
		t.Errorf("a Keston-wide app gets no Keston privileges: %+v", c)
	}
	// Every organisation has it.
	list, err := e.st.ClientsFor(ctx, e.org.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range list {
		found = found || x.ID == id
	}
	if !found {
		t.Error("another organisation doesn't have it")
	}

	// Public apps have no secret.
	code, raw = e.call(staff, http.MethodPost, base, map[string]any{"name": "Keston Mobile", "type": "native",
		"redirectUris": []string{"https://m.example.com/cb"}})
	var pub struct {
		App          kestonAppJSON
		ClientSecret string
	}
	_ = json.Unmarshal(raw, &pub)
	if code != http.StatusCreated || pub.ClientSecret != "" || pub.App.HasSecret {
		t.Errorf("public app: %d %+v", code, pub)
	}
	if code, _ := e.call(staff, http.MethodPost, base, map[string]any{"name": "x", "type": "web", "redirectUris": []string{"http://insecure.example.com"}}); code != http.StatusUnprocessableEntity {
		t.Errorf("insecure redirect: %d", code)
	}

	// Changing it, and a new secret (the old one stops working).
	if code, raw := e.call(staff, http.MethodPatch, base+"/"+id, map[string]any{"name": "Keston Quizzes"}); code != http.StatusOK {
		t.Fatalf("patch: %d %s", code, raw)
	}
	code, raw = e.call(staff, http.MethodPost, base+"/"+id+"/secret", nil)
	var rotated struct{ ClientSecret string }
	_ = json.Unmarshal(raw, &rotated)
	if code != http.StatusOK || rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("new secret: %d %s", code, raw)
	}

	// clients sync: never overwrites it, but does update apps it manages.
	file := &store.Client{ID: id, Name: "From the file", Publisher: "X", Verification: "owned", RedirectURIs: []string{"https://x"},
		PostLogoutRedirectURIs: []string{}, RequiredScopes: []string{"openid"}, OptionalScopes: []string{}}
	if err := e.st.UpsertClient(ctx, file, new(string)); err != nil {
		t.Fatal(err)
	}
	if c, _ = e.st.ClientByID(ctx, id); c.Name != "Keston Quizzes" || c.Verification != "none" || c.SecretHash == nil {
		t.Errorf("sync overwrote an admin-managed app: %+v", c)
	}
	fileID := "file" + secret.Hash(secret.Token())[:8]
	file.ID = fileID
	if err := e.st.UpsertClient(ctx, file, new(string)); err != nil {
		t.Fatal(err)
	}
	file.Name = "File app, changed"
	if err := e.st.UpsertClient(ctx, file, new(string)); err != nil {
		t.Fatal(err)
	}
	if c, _ = e.st.ClientByID(ctx, fileID); c.Name != "File app, changed" || c.ManagedBy != store.ManagedByDeployment {
		t.Errorf("sync didn't update its own app: %+v", c)
	}
	// ...and those can't be edited here.
	if code, _ := e.call(staff, http.MethodPatch, base+"/"+fileID, map[string]any{"name": "Mine now"}); code != http.StatusConflict {
		t.Errorf("edit a deployment-managed app: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPost, base+"/"+fileID+"/retire", nil); code != http.StatusConflict {
		t.Errorf("retire a deployment-managed app: %d", code)
	}

	// Retired: not in anyone's apps and can't be signed in to.
	if code, _ := e.call(staff, http.MethodPost, base+"/"+id+"/retire", nil); code != http.StatusOK {
		t.Fatalf("retire: %d", code)
	}
	list, _ = e.st.ClientsFor(ctx, e.org.ID)
	for _, x := range list {
		if x.ID == id {
			t.Error("a retired app is still listed")
		}
	}
	if c, _ = e.st.ClientByID(ctx, id); c.RetiredAt == nil {
		t.Error("not retired")
	}
	// TKG Admins still see it (to bring it back).
	code, raw = e.call(staff, http.MethodGet, "/organisations/"+platform.ID+"/apps", nil)
	var apps struct{ Apps []appJSON }
	_ = json.Unmarshal(raw, &apps)
	seen := false
	for _, a := range apps.Apps {
		seen = seen || (a.ID == id && a.Retired)
	}
	if code != http.StatusOK || !seen {
		t.Errorf("TKG Admin doesn't see the retired app: %d", code)
	}
	if code, _ := e.call(staff, http.MethodPost, base+"/"+id+"/restore", nil); code != http.StatusOK {
		t.Errorf("restore: %d", code)
	}

	// Audited.
	var n int
	if err := e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action LIKE 'keston_app.%'`,
		platform.ID).Scan(&n); err != nil || n < 5 {
		t.Errorf("audited %d changes: %v", n, err)
	}
}
