package store

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// ── Username formulas ────────────────────────────────────────────────────
//
// How Keston Admin suggests a new user's username from their name
// (Settings → Username format). A formula mixes:
//   {first} {last}     their first or last name
//   {first:2}          its first 2 characters
//   {last:-3}          its last 3 characters
// with letters, numbers, dots, dashes and underscores as they are, e.g.
// {first}.{last} → jo.bloggs, {first:1}{last} → jbloggs.

const DefaultUsernameFormula = "{first}.{last}"

var (
	formulaToken   = regexp.MustCompile(`\{(first|last)(?::(-?[1-9][0-9]?))?\}`)
	formulaLiteral = regexp.MustCompile(`^[a-z0-9._-]*$`)
)

// CheckUsernameFormula: "" if it's a usable formula, otherwise what's wrong.
func CheckUsernameFormula(f string) string {
	if strings.TrimSpace(f) == "" || len(f) > 100 {
		return "Enter a formula, e.g. {first}.{last}"
	}
	if !formulaToken.MatchString(f) {
		return "Use {first} or {last} at least once"
	}
	rest := formulaToken.ReplaceAllString(f, "")
	if strings.ContainsAny(rest, "{}") {
		return "Use {first}, {last}, {first:2} (first 2 characters) or {last:-2} (last 2)"
	}
	if !formulaLiteral.MatchString(rest) {
		return "Between them, use only lowercase letters, numbers, dots, dashes or underscores"
	}
	return ""
}

// namePart: a name in the characters a username allows (accents dropped).
func namePart(s string) string {
	var b strings.Builder
	for _, r := range norm.NFKD.String(strings.ToLower(s)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if unicode.Is(unicode.Mn, r) {
			continue
		}
	}
	return b.String()
}

// ApplyUsernameFormula: the username a formula gives for a name, with
// separators left over from empty parts tidied away.
func ApplyUsernameFormula(f, first, last string) string {
	parts := map[string]string{"first": namePart(first), "last": namePart(last)}
	out := formulaToken.ReplaceAllStringFunc(f, func(tok string) string {
		m := formulaToken.FindStringSubmatch(tok)
		v := parts[m[1]]
		if m[2] == "" {
			return v
		}
		n, _ := strconv.Atoi(m[2])
		switch {
		case n > 0 && n < len(v):
			return v[:n]
		case n < 0 && -n < len(v):
			return v[len(v)+n:]
		}
		return v
	})
	out = regexp.MustCompile(`[._-]{2,}`).ReplaceAllStringFunc(out, func(s string) string { return s[:1] })
	return strings.Trim(out, "._-")
}
