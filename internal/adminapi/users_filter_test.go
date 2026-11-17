package adminapi

import (
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func row(name, email, role string, mods ...func(*userRow)) userRow {
	u := userRow{userJSON: userJSON{Name: name, Email: email, Role: role, Status: "active"}, Licences: []string{}, Roles: []string{}}
	for _, m := range mods {
		m(&u)
	}
	return u
}

func names(rows []userRow) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

func filterFor(t *testing.T, query string) userFilter {
	t.Helper()
	f, ok := userFilterFrom(httptest.NewRecorder(), httptest.NewRequest("GET", "/users?"+query, nil))
	if !ok {
		t.Fatalf("%q rejected", query)
	}
	return f
}

func TestUserFilter(t *testing.T) {
	g1, g2 := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	day := func(d int) func(*userRow) {
		return func(u *userRow) { u.created = time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
	}
	rows := []userRow{
		row("Cara", "cara@x.test", "member", day(3), func(u *userRow) { u.MFA = true; u.Licences = []string{"work"}; u.groups = []string{g1} }),
		row("Ada", "ada@x.test", "global_admin", day(1), func(u *userRow) { u.MFA = true }),
		row("Bob", "bob@x.test", "member", day(2), func(u *userRow) {
			u.Status = "disabled"
			u.Roles = []string{"helpdesk_admin"}
			u.groups = []string{g1, g2}
		}),
		row("Dee", "dee@x.test", "global_admin", day(4), func(u *userRow) { u.PlatformAdmin = true; u.Locked = true }),
	}
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"", []string{"Ada", "Bob", "Cara", "Dee"}},
		{"role=user", []string{"Cara"}},
		{"role=global_admin", []string{"Ada"}},
		{"role=tkg_admin", []string{"Dee"}},
		{"role=user,helpdesk_admin", []string{"Bob", "Cara"}},
		{"status=disabled", []string{"Bob"}},
		{"status=locked&status=disabled", []string{"Bob", "Dee"}},
		{"licence=work", []string{"Cara"}},
		{"licence=none", []string{"Ada", "Bob", "Dee"}},
		{"group=" + g2, []string{"Bob"}},
		{"group=" + g1, []string{"Bob", "Cara"}},
		{"mfa=on", []string{"Ada", "Cara"}},
		{"mfa=off", []string{"Bob", "Dee"}},
		{"q=BOB", []string{"Bob"}},
		{"mfa=on&role=user", []string{"Cara"}},
		{"sort=created", []string{"Ada", "Bob", "Cara", "Dee"}},
		{"sort=created&dir=desc", []string{"Dee", "Cara", "Bob", "Ada"}},
		{"sort=email&dir=desc", []string{"Dee", "Cara", "Bob", "Ada"}},
		{"sort=role&dir=desc", []string{"Dee", "Ada", "Bob", "Cara"}},
		{"sort=status", []string{"Ada", "Cara", "Dee", "Bob"}},
	} {
		if got := names(filterFor(t, c.query).apply(rows)); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.query, got, c.want)
		}
	}
}

func TestUserFilterRejectsJunk(t *testing.T) {
	for _, q := range []string{"status=x", "mfa=maybe", "sort=password", "dir=up", "group=nope"} {
		rec := httptest.NewRecorder()
		if _, ok := userFilterFrom(rec, httptest.NewRequest("GET", "/users?"+q, nil)); ok || rec.Code != 422 && rec.Code != 400 {
			t.Errorf("%q: ok=%v code=%d", q, ok, rec.Code)
		}
	}
}
