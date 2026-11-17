package adminapi

import (
	"slices"
	"testing"

	"github.com/thekestongroup/id/internal/profile"
)

func TestProfileFilterAndSort(t *testing.T) {
	str := func(s string) *string { return &s }
	num := func(f float64) *float64 { return &f }
	prof := func(dept, title, mgrID, mgrName string, attrs map[string]profile.Value) func(*userRow) {
		return func(u *userRow) {
			u.Profile.Department, u.Profile.JobTitle, u.Profile.ManagerID = dept, title, mgrID
			if mgrID != "" {
				u.Profile.Manager = &personRef{ID: mgrID, Name: mgrName}
			}
			u.attrs = attrs
		}
	}
	rows := []userRow{
		row("Ada", "ada@x.test", "member", prof("Science", "Head", "", "", map[string]profile.Value{"grade": {Number: num(10)}})),
		row("Bob", "bob@x.test", "member", prof("science", "Teacher", "m1", "Ada", map[string]profile.Value{"grade": {Number: num(9)}, "house": {Text: str("Red")}})),
		row("Cara", "cara@x.test", "member", prof("Maths", "Teacher", "m1", "Ada", nil)),
		row("Dee", "dee@x.test", "member"),
	}
	for _, c := range []struct {
		query string
		want  []string
	}{
		{"department=science", []string{"Ada", "Bob"}},
		{"department=Science&jobTitle=teacher", []string{"Bob"}},
		{"manager=m1", []string{"Bob", "Cara"}},
		{"manager=none", []string{"Ada", "Dee"}},
		{"attr.house=red", []string{"Bob"}},
		{"attr.house=none", []string{"Ada", "Cara", "Dee"}},
		{"attr.grade=10", []string{"Ada"}},
		{"sort=department", []string{"Cara", "Ada", "Bob", "Dee"}},
		{"sort=department&dir=desc", []string{"Ada", "Bob", "Cara", "Dee"}}, // blanks stay last
		{"sort=manager", []string{"Bob", "Cara", "Ada", "Dee"}},
		{"sort=attr.grade", []string{"Bob", "Ada", "Cara", "Dee"}}, // numeric: 9 before 10
	} {
		if got := names(filterFor(t, c.query).apply(slices.Clone(rows))); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v want %v", c.query, got, c.want)
		}
	}
}
