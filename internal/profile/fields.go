package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ── Built-in profile fields ──────────────────────────────────────────────

// Fields is a person's built-in profile fields. Blank means not set.
type Fields struct {
	JobTitle   string `json:"jobTitle"`
	Department string `json:"department"`
	Office     string `json:"office"`
	Phone      string `json:"phone"`
	Mobile     string `json:"mobile"`
	EmployeeID string `json:"employeeId"`
	// Their manager's user ID ("": none).
	ManagerID string `json:"managerId"`
	// YYYY-MM-DD ("": not set).
	StartDate string `json:"startDate"`
}

const (
	MaxTextLen    = 200
	MaxEmployeeID = 64
)

var e164RE = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// NormalisePhone turns a typed number into E.164 by dropping spaces, dots,
// dashes and brackets. It has to start with + and the country code.
func NormalisePhone(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	clean := strings.NewReplacer(" ", "", ".", "", "-", "", "(", "", ")", "").Replace(s)
	if !e164RE.MatchString(clean) {
		return "", errors.New("Enter the number with its country code, like +44 20 7123 4567")
	}
	return clean, nil
}

// ValidText checks a free-text profile field: single line, not too long.
func ValidText(s string, max int) bool {
	s = strings.TrimSpace(s)
	return utf8.RuneCountInString(s) <= max && !strings.ContainsAny(s, "\r\n\x00")
}

// NormaliseDate reads YYYY-MM-DD (blank: none).
func NormaliseDate(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Year() < 1900 || t.Year() > 2200 {
		return "", errors.New("Enter a date like 2026-09-01")
	}
	return t.Format("2006-01-02"), nil
}

// FieldError is a problem with one profile field.
type FieldError struct{ Field, Message string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

// Normalise trims and validates built-in fields (the manager is checked
// elsewhere: it needs the database).
func (f Fields) Normalise() (Fields, error) {
	for _, t := range []struct {
		name string
		v    *string
		max  int
	}{{"jobTitle", &f.JobTitle, MaxTextLen}, {"department", &f.Department, MaxTextLen},
		{"office", &f.Office, MaxTextLen}, {"employeeId", &f.EmployeeID, MaxEmployeeID}} {
		*t.v = strings.TrimSpace(*t.v)
		if !ValidText(*t.v, t.max) {
			return f, &FieldError{t.name, fmt.Sprintf("Use up to %d characters on one line", t.max)}
		}
	}
	var err error
	if f.Phone, err = NormalisePhone(f.Phone); err != nil {
		return f, &FieldError{"phone", err.Error()}
	}
	if f.Mobile, err = NormalisePhone(f.Mobile); err != nil {
		return f, &FieldError{"mobile", err.Error()}
	}
	if f.StartDate, err = NormaliseDate(f.StartDate); err != nil {
		return f, &FieldError{"startDate", err.Error()}
	}
	return f, nil
}

// ManagerCycle: would making manager the manager of user create a loop
// (user managing themselves, directly or through others)? managerOf maps a
// user to their manager ("" or missing: none).
func ManagerCycle(managerOf map[string]string, user, manager string) bool {
	seen := map[string]bool{}
	for cur := manager; cur != ""; cur = managerOf[cur] {
		if cur == user {
			return true
		}
		if seen[cur] { // an existing loop elsewhere: don't spin
			return false
		}
		seen[cur] = true
	}
	return false
}

// ── Custom attributes ────────────────────────────────────────────────────

const (
	TypeText    = "text"
	TypeNumber  = "number"
	TypeDate    = "date"
	TypeBoolean = "boolean"
	TypeChoice  = "choice"
)

var AttributeTypes = []string{TypeText, TypeNumber, TypeDate, TypeBoolean, TypeChoice}

var attrKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// Keys that mean a built-in field (in CSV headers and filters).
var reservedKeys = map[string]bool{"name": true, "username": true, "email": true, "domain": true, "role": true,
	"job_title": true, "department": true, "office": true, "phone": true, "mobile": true, "employee_id": true,
	"manager": true, "start_date": true, "password": true, "status": true, "groups": true, "id": true}

func ValidAttributeKey(k string) error {
	if !attrKeyRE.MatchString(k) {
		return errors.New("Use lowercase letters, numbers and underscores, starting with a letter, like cost_centre")
	}
	if reservedKeys[k] {
		return errors.New("That key is used by a built-in field. Choose another")
	}
	return nil
}

// MaxChoices in a choice list.
const MaxChoices = 100

// NormaliseChoices trims the list and rejects blanks, duplicates (ignoring
// case) and too many; it must have something in it.
func NormaliseChoices(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !ValidText(c, 100) {
			return nil, errors.New("Each choice can be up to 100 characters on one line")
		}
		if seen[strings.ToLower(c)] {
			return nil, errors.New("Each choice has to be different")
		}
		seen[strings.ToLower(c)] = true
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("Add at least one choice")
	}
	if len(out) > MaxChoices {
		return nil, errors.New("Use up to 100 choices")
	}
	return out, nil
}

// Value is a custom attribute's value, in the field for its type. Exactly one
// is set.
type Value struct {
	Text   *string
	Number *float64
	Date   *string
	Bool   *bool
}

// JSON is how the value is shown: a string, number, or bool.
func (v Value) JSON() any {
	switch {
	case v.Text != nil:
		return *v.Text
	case v.Number != nil:
		return *v.Number
	case v.Date != nil:
		return *v.Date
	case v.Bool != nil:
		return *v.Bool
	}
	return nil
}

// String is the value as text (the CSV and filter form).
func (v Value) String() string {
	switch {
	case v.Text != nil:
		return *v.Text
	case v.Number != nil:
		return strconv.FormatFloat(*v.Number, 'f', -1, 64)
	case v.Date != nil:
		return *v.Date
	case v.Bool != nil:
		if *v.Bool {
			return "yes"
		}
		return "no"
	}
	return ""
}

// ParseValue reads raw (a JSON string, number or bool, or the text from a CSV
// cell) for an attribute of this type. A blank value (nil result) clears it.
func ParseValue(typ string, choices []string, raw json.RawMessage) (*Value, error) {
	var anyv any
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &anyv); err != nil {
		return nil, errors.New("Couldn't read that value")
	}
	switch x := anyv.(type) {
	case string:
		return ParseText(typ, choices, x)
	case float64:
		if typ != TypeNumber {
			return ParseText(typ, choices, strconv.FormatFloat(x, 'f', -1, 64))
		}
		return numberValue(x)
	case bool:
		if typ != TypeBoolean {
			return nil, errors.New("Enter a " + typ)
		}
		return &Value{Bool: &x}, nil
	}
	return nil, errors.New("Couldn't read that value")
}

func numberValue(f float64) (*Value, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) >= 1e15 {
		return nil, errors.New("Enter a smaller number")
	}
	return &Value{Number: &f}, nil
}

// ParseText reads a value typed as text. Blank clears it.
func ParseText(typ string, choices []string, s string) (*Value, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	switch typ {
	case TypeText:
		if !ValidText(s, 500) {
			return nil, errors.New("Use up to 500 characters on one line")
		}
		return &Value{Text: &s}, nil
	case TypeNumber:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, errors.New("Enter a number")
		}
		return numberValue(f)
	case TypeDate:
		d, err := NormaliseDate(s)
		if err != nil {
			return nil, err
		}
		return &Value{Date: &d}, nil
	case TypeBoolean:
		switch strings.ToLower(s) {
		case "yes", "y", "true", "1":
			t := true
			return &Value{Bool: &t}, nil
		case "no", "n", "false", "0":
			f := false
			return &Value{Bool: &f}, nil
		}
		return nil, errors.New("Enter yes or no")
	case TypeChoice:
		for _, c := range choices {
			if strings.EqualFold(c, s) {
				return &Value{Text: &c}, nil
			}
		}
		return nil, errors.New("Choose one of: " + strings.Join(choices, ", "))
	}
	return nil, errors.New("Unknown attribute type")
}

// ── Changing fields from a request ───────────────────────────────────────

// FieldKeys are the JSON names of the built-in fields.
var FieldKeys = []string{"jobTitle", "department", "office", "phone", "mobile", "employeeId", "managerId", "startDate"}

func (f *Fields) ptr(key string) *string {
	switch key {
	case "jobTitle":
		return &f.JobTitle
	case "department":
		return &f.Department
	case "office":
		return &f.Office
	case "phone":
		return &f.Phone
	case "mobile":
		return &f.Mobile
	case "employeeId":
		return &f.EmployeeID
	case "managerId":
		return &f.ManagerID
	case "startDate":
		return &f.StartDate
	}
	return nil
}

// Get is a field's value by its JSON name.
func (f Fields) Get(key string) string {
	if p := f.ptr(key); p != nil {
		return *p
	}
	return ""
}

// Patch applies the fields present in body (a string, or null to clear) to f,
// and validates the result. allow says whether the caller may change a field
// (called only for fields whose value actually changes); the error then is a
// *FieldError with Message "forbidden".
func (f Fields) Patch(body map[string]json.RawMessage, allow func(key string) bool) (Fields, error) {
	out := f
	for _, key := range FieldKeys {
		raw, ok := body[key]
		if !ok {
			continue
		}
		var v *string
		if err := json.Unmarshal(raw, &v); err != nil {
			return f, &FieldError{key, "Enter text"}
		}
		val := ""
		if v != nil {
			val = strings.TrimSpace(*v)
		}
		if val == strings.TrimSpace(f.Get(key)) {
			continue
		}
		if allow != nil && !allow(key) {
			return f, &FieldError{key, "forbidden"}
		}
		*out.ptr(key) = val
	}
	return out.Normalise()
}
