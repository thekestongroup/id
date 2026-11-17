//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

// getNames: GET path and the given field of each item in the array at key
// ("" for the body itself).
func (e *env) getList(as *store.User, path, key string) []map[string]any {
	e.t.Helper()
	code, raw := e.do(as, http.MethodGet, path, nil)
	if code != http.StatusOK {
		e.t.Fatalf("%s: %d %s", path, code, raw)
	}
	if key == "" {
		var out []map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			e.t.Fatal(err)
		}
		return out
	}
	var wrap map[string][]map[string]any
	if err := json.Unmarshal(raw, &wrap); err != nil {
		e.t.Fatal(err)
	}
	return wrap[key]
}

func field(items []map[string]any, f string) []string {
	out := []string{}
	for _, it := range items {
		s, _ := it[f].(string)
		out = append(out, s)
	}
	return out
}

func TestUsersListFilters(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	ann, ben, cal := e.user("ann", "member"), e.user("ben", "member"), e.user("cal", "member")
	staff := e.group("Staff")
	for _, u := range []*store.User{ann, ben} {
		if err := e.st.AddGroupMember(ctx, staff.ID, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := e.st.SetLicences(ctx, ann.ID, nil, []string{"work"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.st.SetRoles(ctx, ben.ID, []string{"helpdesk_admin"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetUserStatus(ctx, cal.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB.Exec(ctx, `UPDATE users SET totp_enabled = true WHERE id = $1`, ann.ID); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		query string
		want  []string
	}{
		{"", []string{"Ada Admin", "ann", "ben", "cal"}},
		{"?role=user", []string{"ann", "cal"}},
		{"?role=global_admin", []string{"Ada Admin"}},
		{"?role=helpdesk_admin", []string{"ben"}},
		{"?status=disabled", []string{"cal"}},
		{"?status=active&role=user", []string{"ann"}},
		{"?licence=work", []string{"Ada Admin", "ann"}}, // the first admin gets every product
		{"?group=" + staff.ID, []string{"ann", "ben"}},
		{"?mfa=on", []string{"ann"}},
		{"?mfa=off&group=" + staff.ID, []string{"ben"}},
		{"?sort=email&dir=desc", []string{"cal", "ben", "ann", "Ada Admin"}},
		{"?q=AN", []string{"ann"}},
	} {
		got := field(e.getList(admin, "/users"+c.query, ""), "name")
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.query, got, c.want)
		}
	}
	if code, _ := e.do(admin, http.MethodGet, "/users?sort=bogus", nil); code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
		t.Errorf("bad sort: %d", code)
	}
}

func TestGroupsListFilters(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	big := e.group("Big", store.PermViewUsers)
	mid := e.group("Mid")
	e.group("Empty")
	for i, name := range []string{"u1", "u2", "u3"} {
		u := e.user(name, "member")
		if err := e.st.AddGroupMember(ctx, big.ID, u.ID); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := e.st.AddGroupMember(ctx, mid.ID, u.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"", []string{"Big", "Empty", "Mid"}},
		{"?members=gt:1", []string{"Big"}},
		{"?members=gte:1", []string{"Big", "Mid"}},
		{"?members=lt:1", []string{"Empty"}},
		{"?members=eq:1", []string{"Mid"}},
		{"?permissions=yes", []string{"Big"}},
		{"?permissions=no", []string{"Empty", "Mid"}},
		{"?permissions=no&members=gt:0", []string{"Mid"}},
		{"?sort=members&dir=desc", []string{"Big", "Mid", "Empty"}},
		{"?sort=permissions&dir=desc", []string{"Big", "Empty", "Mid"}},
		{"?q=mi", []string{"Mid"}},
	} {
		got := field(e.getList(admin, "/groups"+c.query, ""), "name")
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.query, got, c.want)
		}
	}
	for _, q := range []string{"?members=12", "?members=bad:1", "?members=gt:x", "?permissions=maybe", "?sort=x"} {
		if code, _ := e.do(admin, http.MethodGet, "/groups"+q, nil); code == http.StatusOK {
			t.Errorf("%q accepted", q)
		}
	}
}

func TestLogsMultiValueFilters(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	a, b, c := e.user("ann", "member"), e.user("ben", "member"), e.user("cal", "member")
	for _, u := range []*store.User{a, b, c} {
		e.st.LogSignIn(ctx, store.SignIn{User: u, Method: store.SignInPassword, Reason: store.ReasonWrongPassword})
		e.st.LogSignIn(ctx, store.SignIn{User: u, Method: store.SignInPassword, Reason: store.ReasonLocked})
		e.st.Audit(ctx, store.AuditEntry{OrganisationID: e.org.ID, Actor: admin, Action: store.ActionUserUpdated,
			TargetType: store.TargetUser, TargetID: u.ID, TargetName: u.Name})
	}
	count := func(path, key string) int { return len(e.getList(admin, path, key)) }

	one := url.Values{"user": {a.ID}}.Encode()
	two := url.Values{"user": {a.ID, b.ID}}.Encode()
	csv := url.Values{"user": {a.ID + "," + b.ID}}.Encode()
	for q, want := range map[string]int{one: 2, two: 4, csv: 4} {
		if got := count("/sign-ins?"+q, "entries"); got != want {
			t.Errorf("sign-ins ?%s: %d, want %d", q, got, want)
		}
	}
	// Admin actions about either of them (the admin did them all, so one user filter is about the target).
	if got := count("/audit-log?"+two+"&action=user.updated", "entries"); got != 2 {
		t.Errorf("audit-log two users: %d, want 2", got)
	}
	reasons := url.Values{"reason": {store.ReasonWrongPassword, store.ReasonLocked}}.Encode()
	if got := count("/sign-ins?"+reasons, "entries"); got != 6 {
		t.Errorf("two reasons: %d, want 6", got)
	}
	if got := count("/sign-ins?reason=locked&"+two, "entries"); got != 2 {
		t.Errorf("one reason, two users: %d, want 2", got)
	}
	if got := count("/sign-ins?reason="+store.ReasonWrongPassword+"&reason="+store.ReasonLocked+"&result=failure", "entries"); got != 6 {
		t.Errorf("reasons+failure: %d, want 6", got)
	}
	if code, _ := e.do(admin, http.MethodGet, "/sign-ins?user=nope", nil); code == http.StatusOK {
		t.Error("bad user accepted")
	}
}

func TestBulkGroupMembers(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	helper := e.user("helper", "member")
	if err := e.st.AddGroupMember(ctx, e.group("Group managers", store.PermGroups).ID, helper.ID); err != nil {
		t.Fatal(err)
	}
	ann, ben := e.user("ann", "member"), e.user("ben", "member")
	boss := e.user("boss", "global_admin")
	g1, g2 := e.group("One"), e.group("Two")
	powerful := e.group("Powerful", store.PermUserStatus)
	if err := e.st.AddGroupMember(ctx, g1.ID, ben.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddGroupMember(ctx, g2.ID, ann.ID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		Groups       []groupResult
		SkippedUsers []bulkResult
	}
	run := func(as *store.User, body map[string]any) (int, result) {
		code, raw := e.do(as, http.MethodPost, "/groups/bulk/members", body)
		var out result
		_ = json.Unmarshal(raw, &out)
		return code, out
	}
	members := func(g *store.Group) []string {
		m, err := e.st.GroupMembers(ctx, g.ID)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, u := range m {
			out = append(out, u.Name)
		}
		return out
	}
	auditCount := func(action string) int {
		var n int
		if err := e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action = $2`,
			e.org.ID, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Add ann and ben to both groups, take ben out of One: ben is in One
	// already, so adding him there does nothing; the same user can't be in both lists.
	code, res := run(admin, map[string]any{"groupIds": []string{g1.ID, g2.ID}, "add": ids(ann, ben)})
	if code != http.StatusOK {
		t.Fatalf("add: %d", code)
	}
	if len(res.Groups) != 2 || len(res.Groups[0].Added) != 2 && len(res.Groups[1].Added) != 1 {
		t.Errorf("add result: %+v", res.Groups)
	}
	byName := map[string]groupResult{}
	for _, g := range res.Groups {
		byName[g.Name] = g
	}
	if g := byName["One"]; len(g.Added) != 1 || g.Added[0].Name != "ann" || g.MemberCount != 2 || g.Result != "done" {
		t.Errorf("One: %+v", g)
	}
	if g := byName["Two"]; len(g.Added) != 1 || g.Added[0].Name != "ben" || g.MemberCount != 2 {
		t.Errorf("Two: %+v", g)
	}
	if got := auditCount(store.ActionGroupMemberAdded); got != 2 {
		t.Errorf("added audit entries: %d, want 2 (only real changes)", got)
	}

	// Again: nothing to do.
	_, res = run(admin, map[string]any{"groupIds": []string{g1.ID}, "add": ids(ann)})
	if res.Groups[0].Result != "skipped" || res.Groups[0].Reason != "Already up to date." {
		t.Errorf("repeat: %+v", res.Groups[0])
	}

	// Remove.
	_, res = run(admin, map[string]any{"groupIds": []string{g1.ID, g2.ID}, "remove": ids(ann)})
	if len(res.Groups[0].Removed)+len(res.Groups[1].Removed) != 2 {
		t.Errorf("remove: %+v", res.Groups)
	}
	if got := members(g1); !slices.Equal(got, []string{"ben"}) {
		t.Errorf("One members: %v", got)
	}
	if got := auditCount(store.ActionGroupMemberRemoved); got != 2 {
		t.Errorf("removed audit entries: %d, want 2", got)
	}

	// A group that gives permissions the caller lacks is skipped, as is a global admin
	// the caller can't change; the rest still happens.
	code, res = run(helper, map[string]any{"groupIds": []string{g1.ID, powerful.ID}, "add": ids(ann, boss)})
	if code != http.StatusOK {
		t.Fatalf("helper: %d", code)
	}
	byName = map[string]groupResult{}
	for _, g := range res.Groups {
		byName[g.Name] = g
	}
	if g := byName["Powerful"]; g.Result != "skipped" || g.Reason == "" {
		t.Errorf("Powerful: %+v", g)
	}
	if g := byName["One"]; g.Result != "done" || len(g.Added) != 1 || g.Added[0].Name != "ann" {
		t.Errorf("One for helper: %+v", g)
	}
	if len(res.SkippedUsers) != 1 || res.SkippedUsers[0].ID != boss.ID {
		t.Errorf("skipped users: %+v", res.SkippedUsers)
	}
	if got := members(powerful); len(got) != 0 {
		t.Errorf("Powerful changed: %v", got)
	}

	// Bad requests.
	for name, body := range map[string]map[string]any{
		"no groups":  {"add": ids(ann)},
		"no users":   {"groupIds": []string{g1.ID}},
		"both lists": {"groupIds": []string{g1.ID}, "add": ids(ann), "remove": ids(ann)},
	} {
		if code, _ := run(admin, body); code == http.StatusOK {
			t.Errorf("%s accepted", name)
		}
	}
	// Someone with no group or assign permission can't.
	if code, _ := run(ann, map[string]any{"groupIds": []string{g1.ID}, "add": ids(ben)}); code == http.StatusOK {
		t.Error("ann (no permissions) changed groups")
	}
}
