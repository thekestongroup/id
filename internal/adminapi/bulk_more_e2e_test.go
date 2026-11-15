//go:build e2e

package adminapi

import (
	"context"
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
