package store

import "testing"

func TestUsernameFormula(t *testing.T) {
	for _, c := range []struct{ f, first, last, want string }{
		{"{first}.{last}", "Jo", "Bloggs", "jo.bloggs"},
		{"{first:1}{last}", "Jo", "Bloggs", "jbloggs"},
		{"{first:1}.{last}", "Zoë", "O'Brien", "z.obrien"},
		{"{last:-2}{first}", "Jo", "Bloggs", "gsjo"},
		{"{first:3}_{last:3}", "Jo", "Bloggs", "jo_blo"},
		{"{first}.{last}", "Jo", "", "jo"},
		{"staff-{first:1}{last}", "Jo", "Bloggs", "staff-jbloggs"},
	} {
		if got := ApplyUsernameFormula(c.f, c.first, c.last); got != c.want {
			t.Errorf("%s with %s %s: %q, want %q", c.f, c.first, c.last, got, c.want)
		}
	}
	for f, ok := range map[string]bool{
		"{first}.{last}": true, "{first:1}{last}": true, "{last:-3}": true, "x{first}": true,
		"": false, "jo.bloggs": false, "{middle}": false, "{first} {last}": false, "{first:0}": false, "{First}": false,
	} {
		if got := CheckUsernameFormula(f) == ""; got != ok {
			t.Errorf("%q: valid %v, want %v (%s)", f, got, ok, CheckUsernameFormula(f))
		}
	}
}
