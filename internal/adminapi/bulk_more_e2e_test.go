//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
)

// One password for everyone, or each their own, and whether they must
// change it.
func TestBulkResetOptions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	a, b := e.user("amy", "member"), e.user("bob", "member")

	res := e.bulk(admin, "/users/bulk/reset-password", map[string]any{"userIds": ids(a, b),
		"password": "Shared-Secret-917", "requirePasswordChange": false})
	for _, u := range []string{a.ID, b.ID} {
		if res[u].Result != "done" || res[u].Password != "" {
			t.Errorf("same password: %+v", res[u])
		}
		got, _ := e.st.UserByID(ctx, u)
		if ok, _ := secret.CheckPassword(got.PasswordHash, "Shared-Secret-917"); !ok {
			t.Errorf("%s: the shared password doesn't work", got.Name)
		}
		if st, _ := e.st.SignInState(ctx, got); st.PasswordChangeRequired {
			t.Errorf("%s: change required, but requirePasswordChange was false", got.Name)
		}
	}

	// A password that's someone's username: they're skipped.
	pw := e.user("correcthorse99", "member")
	res = e.bulk(admin, "/users/bulk/reset-password", map[string]any{"userIds": ids(a, pw),
		"password": "correcthorse99"})
	if res[pw.ID].Result != "skipped" {
		t.Errorf("username as password: %+v", res[pw.ID])
	}

	// Too weak for anyone: refused outright.
	if code, _ := e.do(admin, http.MethodPost, "/users/bulk/reset-password", map[string]any{"userIds": ids(a),
		"password": "short"}); code != http.StatusUnprocessableEntity {
		t.Errorf("weak shared password: %d", code)
	}

	// Generated (the default): each their own, change required.
	res = e.bulk(admin, "/users/bulk/reset-password", map[string]any{"userIds": ids(a, b)})
	if res[a.ID].Password == "" || res[a.ID].Password == res[b.ID].Password {
		t.Errorf("generated: %+v %+v", res[a.ID], res[b.ID])
	}
	got, _ := e.st.UserByID(ctx, a.ID)
	if st, _ := e.st.SignInState(ctx, got); !st.PasswordChangeRequired {
		t.Error("generated: change should be required by default")
	}
}

func TestBulkGroups(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	a, b := e.user("amy", "member"), e.user("bob", "member")
	staff, office, old := e.group("Staff"), e.group("Office"), e.group("Old team")
	_ = e.st.AddGroupMember(ctx, old.ID, a.ID)
	_ = e.st.AddGroupMember(ctx, staff.ID, b.ID)

	res := e.bulk(admin, "/users/bulk/groups", map[string]any{"userIds": ids(a, b),
		"add": []string{staff.ID, office.ID}, "remove": []string{old.ID}})
	if res[a.ID].Result != "done" || res[b.ID].Result != "done" {
		t.Errorf("results: %+v", res)
	}
	in := func(groupID, userID string) bool {
		list, _ := e.st.GroupMembers(ctx, groupID)
		for _, m := range list {
			if m.ID == userID {
				return true
			}
		}
		return false
	}
	if !in(staff.ID, a.ID) || !in(office.ID, a.ID) || in(old.ID, a.ID) || !in(office.ID, b.ID) {
		t.Error("memberships not as asked")
	}

	// Nothing to change: skipped.
	res = e.bulk(admin, "/users/bulk/groups", map[string]any{"userIds": ids(a), "add": []string{staff.ID}})
	if res[a.ID].Result != "skipped" {
		t.Errorf("no change: %+v", res[a.ID])
	}

	// The same group in both lists, or none at all: refused.
	if code, _ := e.do(admin, http.MethodPost, "/users/bulk/groups", map[string]any{"userIds": ids(a),
		"add": []string{staff.ID}, "remove": []string{staff.ID}}); code != http.StatusUnprocessableEntity {
		t.Errorf("both lists: %d", code)
	}
	if code, _ := e.do(admin, http.MethodPost, "/users/bulk/groups", map[string]any{"userIds": ids(a)}); code !=
		http.StatusUnprocessableEntity {
		t.Errorf("no groups: %d", code)
	}

	// A group giving permissions the caller lacks: refused.
	helper := e.user("helper", "member")
	helpers := e.group("Helpers", "groups.manage")
	_ = e.st.AddGroupMember(ctx, helpers.ID, helper.ID)
	admins := e.group("Admins", "users.delete")
	if code, _ := e.do(helper, http.MethodPost, "/users/bulk/groups", map[string]any{"userIds": ids(a),
		"add": []string{admins.ID}}); code != http.StatusForbidden {
		t.Errorf("group with more permissions: %d", code)
	}
}

// Adding a list of users: each gets their own password and the licences;
// rows that can't be added are skipped and the rest still are.
func TestBulkCreate(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	admin := e.admin()
	e.user("taken", "member")
	code, raw := e.do(admin, http.MethodPost, "/users/bulk/create", map[string]any{
		"licences": []string{"work"},
		"users": []map[string]string{
			{"name": "Amy Adams", "username": "amy.adams"},
			{"name": "Ben Brown", "username": "Ben.Brown"},
			{"name": "", "username": "noname"},
			{"name": "Taken", "username": "taken"},
			{"name": "Amy Again", "username": "amy.adams"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create: %d %s", code, raw)
	}
	var out struct{ Results []bulkResult }
	_ = json.Unmarshal(raw, &out)
	want := []string{"done", "done", "skipped", "skipped", "skipped"}
	for i, r := range out.Results {
		if r.Result != want[i] {
			t.Errorf("row %d: %+v, want %s", i, r, want[i])
		}
	}
	amy := out.Results[0]
	if amy.Password == "" || amy.Password == out.Results[1].Password || amy.Email != "amy.adams@"+e.org.Domain {
		t.Errorf("Amy: %+v", amy)
	}
	u, err := e.st.UserByID(ctx, amy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := secret.CheckPassword(u.PasswordHash, amy.Password); !ok {
		t.Error("Amy's password doesn't work")
	}
	if st, _ := e.st.SignInState(ctx, u); !st.PasswordChangeRequired {
		t.Error("Amy should change her password at first sign-in")
	}
	if l, _ := e.st.Licences(ctx, u.ID); len(l) != 1 || l[0] != "work" {
		t.Errorf("Amy's licences: %v", l)
	}
	if u.Role != "member" {
		t.Errorf("Amy's role: %s", u.Role)
	}

	// Licences need "Assign licences".
	helper := e.user("helper", "member")
	g := e.group("Helpdesk", "users.create")
	_ = e.st.AddGroupMember(ctx, g.ID, helper.ID)
	if code, _ := e.do(helper, http.MethodPost, "/users/bulk/create", map[string]any{
		"licences": []string{"work"}, "users": []map[string]string{{"name": "Cat", "username": "cat"}},
	}); code != http.StatusUnprocessableEntity {
		t.Errorf("licences without the permission: %d", code)
	}
}
