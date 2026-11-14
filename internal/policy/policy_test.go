package policy

import (
	"slices"
	"testing"
)

func ids(rules []Rule) []string {
	out := []string{}
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

func TestBaseline(t *testing.T) {
	var p Policy // no organisation rules
	cases := map[string][]string{
		"short":                 {"length"},
		"correct horse battery": {},
		"password":              {"common"},
		"Password1!":            {"common"}, // trailing numbers and symbols taken off
		"Summer2024":            {"common"},
		"QWERTYUIOP":            {"common"}, // case doesn't matter
		"123456":                {"length", "common"},
		"blue kettle drum":      {},
	}
	for pw, want := range cases {
		if got := ids(p.Check(pw)); !slices.Equal(got, want) {
			t.Errorf("Check(%q) = %v, want %v", pw, got, want)
		}
	}
}

func TestOrganisationRules(t *testing.T) {
	p := Policy{MinLength: 10, MinUppercase: 1, MinDigits: 2, MinSpecial: 3, Blocked: []string{"  Greenfield "}}
	cases := map[string][]string{
		"abcdefghij":         {"uppercase", "digits", "special"},
		"Thamesbank12!!!":    {},
		"Abc12!!!":           {"length"},
		"Greenfield":         {"digits", "special", "common"}, // on the organisation's own list
		"Greenfield12!!!":    {"common"},
		"Thames River 42?!#": {},
	}
	for pw, want := range cases {
		if got := ids(p.Check(pw)); !slices.Equal(got, want) {
			t.Errorf("Check(%q) = %v, want %v", pw, got, want)
		}
	}
}

func TestNeverWeakerThanBaseline(t *testing.T) {
	p := Policy{MinLength: 4, MinDigits: -2}.Normalise()
	if p.MinLength != BaselineMinLength || p.MinDigits != 0 {
		t.Fatalf("Normalise = %+v, want min length %d and no negative counts", p, BaselineMinLength)
	}
}

func TestAvoid(t *testing.T) {
	if got := ids(Policy{}.Check("headoffice", "headoffice")); !slices.Equal(got, []string{"common"}) {
		t.Errorf("password equal to the username should fail, got %v", got)
	}
}

func TestMessage(t *testing.T) {
	p := Policy{MinDigits: 1}
	if got := Message(p.Check("password")); got != "Your password needs at least 1 number, and can't be a commonly used password." {
		t.Errorf("Message = %q", got)
	}
	if got := Message(p.Check("Password1")); got != "That password is too easy to guess. Choose a different one." {
		t.Errorf("Message = %q", got)
	}
}
