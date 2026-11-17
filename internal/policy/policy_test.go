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

func TestMinLengthRaisedToWhatIsRequired(t *testing.T) {
	cases := []struct {
		p    Policy
		want int
	}{
		{Policy{MinLength: 8, MinUppercase: 5, MinLowercase: 5, MinDigits: 5, MinSpecial: 5}, 20},
		{Policy{MinLength: 14, MinUppercase: 1, MinLowercase: 1, MinDigits: 1, MinSpecial: 1}, 14}, // already long enough
		{Policy{MinLength: 12, MinDigits: 1}, 12},
		{Policy{MinUppercase: 32, MinLowercase: 32, MinDigits: 32, MinSpecial: 32}, 128},
		{Policy{MinLength: 100, MinUppercase: 32, MinLowercase: 32, MinDigits: 32, MinSpecial: 32}, 128}, // never above the maximum
		{Policy{MinLength: 9, MinDigits: 1, MinSpecial: -5}, 9},                                          // negative counts add nothing
	}
	for _, c := range cases {
		if got := c.p.Normalise().MinLength; got != c.want {
			t.Errorf("%+v: MinLength = %d, want %d", c.p, got, c.want)
		}
	}
	// A password that has every kind required but is shorter than they add up to fails the length rule.
	p := Policy{MinUppercase: 5, MinLowercase: 5, MinDigits: 5, MinSpecial: 5}
	if got := ids(p.Check("Aa1!Aa1!")); !slices.Contains(got, "length") {
		t.Errorf("an 8-character password should fail a policy needing 20 characters, got %v", got)
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
