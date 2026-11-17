package profile

import (
	"encoding/json"
	"testing"
)

func TestNormalisePhone(t *testing.T) {
	for in, want := range map[string]string{"": "", " +44 (20) 7123-4567 ": "+442071234567", "+1.415.555.2671": "+14155552671"} {
		got, err := NormalisePhone(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"020 7123 4567", "+0123456789", "+44", "+44abc1234567", "+1234567890123456"} {
		if _, err := NormalisePhone(in); err == nil {
			t.Errorf("%q should be rejected", in)
		}
	}
}

func TestFieldsNormalise(t *testing.T) {
	f, err := Fields{JobTitle: " Teacher ", Phone: "+44 20 7123 4567", StartDate: "2026-09-01"}.Normalise()
	if err != nil || f.JobTitle != "Teacher" || f.Phone != "+442071234567" {
		t.Fatalf("%+v %v", f, err)
	}
	for field, bad := range map[string]Fields{
		"jobTitle":   {JobTitle: "a\nb"},
		"department": {Department: string(make([]rune, 201))},
		"mobile":     {Mobile: "07700 900123"},
		"startDate":  {StartDate: "01/09/2026"},
		"employeeId": {EmployeeID: string(make([]byte, 65))},
	} {
		_, err := bad.Normalise()
		fe, ok := err.(*FieldError)
		if !ok || fe.Field != field {
			t.Errorf("%s: got %v", field, err)
		}
	}
	if _, err := (Fields{StartDate: "2026-02-30"}).Normalise(); err == nil {
		t.Error("impossible date accepted")
	}
}

func TestManagerCycle(t *testing.T) {
	// c → b → a (c reports to b, b to a)
	m := map[string]string{"c": "b", "b": "a"}
	for _, tc := range []struct {
		user, mgr string
		want      bool
	}{
		{"a", "a", true},  // themselves
		{"a", "c", true},  // a managed by their own report's report
		{"a", "b", true},  // by a direct report
		{"c", "a", false}, // skip level is fine
		{"b", "x", false}, // someone outside
		{"x", "c", false},
	} {
		if got := ManagerCycle(m, tc.user, tc.mgr); got != tc.want {
			t.Errorf("%s managed by %s: got %v want %v", tc.user, tc.mgr, got, tc.want)
		}
	}
	// A loop that already exists elsewhere doesn't hang.
	if ManagerCycle(map[string]string{"p": "q", "q": "p"}, "x", "p") {
		t.Error("unrelated loop reported")
	}
}

func TestAttributeKey(t *testing.T) {
	for _, k := range []string{"cost_centre", "a", "x9"} {
		if err := ValidAttributeKey(k); err != nil {
			t.Errorf("%q: %v", k, err)
		}
	}
	for _, k := range []string{"", "Cost", "9x", "has space", "department", "manager", "a-b"} {
		if ValidAttributeKey(k) == nil {
			t.Errorf("%q should be rejected", k)
		}
	}
}

func TestChoices(t *testing.T) {
	got, err := NormaliseChoices([]string{" Red ", "", "Blue"})
	if err != nil || len(got) != 2 || got[0] != "Red" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{{}, {" "}, {"a", "A"}} {
		if _, err := NormaliseChoices(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestParseValue(t *testing.T) {
	choices := []string{"Red", "Blue"}
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	ok := []struct {
		typ, in, want string
	}{
		{TypeText, `"Hello"`, "Hello"},
		{TypeNumber, `12.5`, "12.5"},
		{TypeNumber, `"7"`, "7"},
		{TypeDate, `"2026-09-01"`, "2026-09-01"},
		{TypeBoolean, `true`, "yes"},
		{TypeBoolean, `"No"`, "no"},
		{TypeChoice, `"blue"`, "Blue"},
	}
	for _, tc := range ok {
		v, err := ParseValue(tc.typ, choices, raw(tc.in))
		if err != nil || v == nil || v.String() != tc.want {
			t.Errorf("%s %s: %v %v", tc.typ, tc.in, v, err)
		}
	}
	bad := []struct{ typ, in string }{
		{TypeNumber, `"abc"`}, {TypeNumber, `true`}, {TypeDate, `"tomorrow"`}, {TypeBoolean, `"maybe"`},
		{TypeBoolean, `3`}, {TypeChoice, `"Green"`}, {TypeText, `{}`}, {TypeNumber, `1e300`},
	}
	for _, tc := range bad {
		if v, err := ParseValue(tc.typ, choices, raw(tc.in)); err == nil {
			t.Errorf("%s %s accepted: %v", tc.typ, tc.in, v)
		}
	}
	for _, in := range []string{`null`, `""`, ``} {
		if v, err := ParseValue(TypeText, nil, raw(in)); err != nil || v != nil {
			t.Errorf("%q should clear: %v %v", in, v, err)
		}
	}
}

func TestPatch(t *testing.T) {
	cur := Fields{JobTitle: "Teacher", Department: "Maths", Phone: "+442071234567"}
	body := map[string]json.RawMessage{"department": json.RawMessage(`"Science"`), "phone": json.RawMessage(`null`),
		"mobile": json.RawMessage(`"+44 7700 900123"`), "unknown": json.RawMessage(`1`)}
	got, err := cur.Patch(body, nil)
	if err != nil || got.Department != "Science" || got.Phone != "" || got.Mobile != "+447700900123" || got.JobTitle != "Teacher" {
		t.Fatalf("%+v %v", got, err)
	}
	// Only changes are checked against what's allowed.
	only := func(k string) bool { return k == "phone" || k == "mobile" }
	_, err = cur.Patch(map[string]json.RawMessage{"jobTitle": json.RawMessage(`"Teacher"`), "phone": json.RawMessage(`"+442079999999"`)}, only)
	if err != nil {
		t.Errorf("unchanged field shouldn't count: %v", err)
	}
	_, err = cur.Patch(map[string]json.RawMessage{"department": json.RawMessage(`"Art"`)}, only)
	if fe, ok := err.(*FieldError); !ok || fe.Field != "department" || fe.Message != "forbidden" {
		t.Errorf("got %v", err)
	}
	if _, err = cur.Patch(map[string]json.RawMessage{"phone": json.RawMessage(`"123"`)}, nil); err == nil {
		t.Error("bad phone accepted")
	}
	if _, err = cur.Patch(map[string]json.RawMessage{"office": json.RawMessage(`5`)}, nil); err == nil {
		t.Error("number for text accepted")
	}
}
