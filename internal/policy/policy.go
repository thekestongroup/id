// Package policy checks passwords against Keston's baseline rules and an
// organisation's own.
//
// Baseline (set by The Keston Group, always applies):
//   - at least 8 characters
//   - not a commonly used password (common-passwords.txt)
//
// Each organisation can add to it: a longer minimum, at least N capitals,
// lowercase letters, digits or special characters, and its own banned
// passwords. It can make the rules stricter, never weaker.
package policy

import (
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BaselineMinLength is the shortest password any organisation can allow.
const BaselineMinLength = 8

// MaxLength stops very long inputs being hashed (Argon2 cost).
const MaxLength = 256

//go:embed common-passwords.txt
var commonList string

// common holds the baseline banned passwords, lowercase.
var common = func() map[string]struct{} {
	set := map[string]struct{}{}
	for _, line := range strings.Split(commonList, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			set[strings.ToLower(line)] = struct{}{}
		}
	}
	return set
}()

// Policy is an organisation's own rules, stored as JSON. Zero values add
// nothing to the baseline.
type Policy struct {
	MinLength    int      `json:"minLength"`
	MinUppercase int      `json:"minUppercase"`
	MinLowercase int      `json:"minLowercase"`
	MinDigits    int      `json:"minDigits"`
	MinSpecial   int      `json:"minSpecial"`
	Blocked      []string `json:"blocked"`
}

// Normalise keeps a policy within sensible bounds: never below the
// baseline, no negative counts, banned passwords lowercase and unique. The
// minimum length is also raised to what the required kinds of character add
// up to (2 capitals + 2 numbers can't be met in fewer than 4 characters), so
// the length shown to people is the real shortest password.
func (p Policy) Normalise() Policy {
	clamp := func(n, hi int) int { return min(max(n, 0), hi) }
	p.MinUppercase = clamp(p.MinUppercase, 32)
	p.MinLowercase = clamp(p.MinLowercase, 32)
	p.MinDigits = clamp(p.MinDigits, 32)
	p.MinSpecial = clamp(p.MinSpecial, 32)
	required := p.MinUppercase + p.MinLowercase + p.MinDigits + p.MinSpecial
	p.MinLength = min(max(p.MinLength, BaselineMinLength, required), 128)
	blocked := []string{}
	for _, b := range p.Blocked {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" && len(b) <= 128 && !slices.Contains(blocked, b) {
			blocked = append(blocked, b)
		}
	}
	slices.Sort(blocked)
	if len(blocked) > 1000 {
		blocked = blocked[:1000]
	}
	p.Blocked = blocked
	return p
}

// Rule is one requirement, as shown to people setting a password.
type Rule struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Baseline rules can't be turned off by an organisation.
	Baseline bool `json:"baseline"`
	// Min is how many it asks for (characters, capitals, numbers…), so a
	// client can check as someone types. Zero for "common".
	Min int `json:"min,omitempty"`
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Rules lists what a password must meet, in the order to show them.
func (p Policy) Rules() []Rule {
	p = p.Normalise()
	rules := []Rule{{ID: "length", Label: fmt.Sprintf("At least %d characters", p.MinLength), Baseline: p.MinLength == BaselineMinLength, Min: p.MinLength}}
	if p.MinUppercase > 0 {
		rules = append(rules, Rule{ID: "uppercase", Label: "At least " + plural(p.MinUppercase, "capital letter", "capital letters"), Min: p.MinUppercase})
	}
	if p.MinLowercase > 0 {
		rules = append(rules, Rule{ID: "lowercase", Label: "At least " + plural(p.MinLowercase, "lowercase letter", "lowercase letters"), Min: p.MinLowercase})
	}
	if p.MinDigits > 0 {
		rules = append(rules, Rule{ID: "digits", Label: "At least " + plural(p.MinDigits, "number", "numbers"), Min: p.MinDigits})
	}
	if p.MinSpecial > 0 {
		rules = append(rules, Rule{ID: "special", Label: "At least " + plural(p.MinSpecial, "special character", "special characters") + ", like ! ? # or %", Min: p.MinSpecial})
	}
	rules = append(rules, Rule{ID: "common", Label: "Not a commonly used password", Baseline: true})
	return rules
}

// Check returns the rules a password doesn't meet (none: it's fine).
// avoid is extra words it mustn't be, e.g. the username or organisation.
func (p Policy) Check(password string, avoid ...string) []Rule {
	p = p.Normalise()
	var upper, lower, digits, special int
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper++
		case unicode.IsLower(r):
			lower++
		case unicode.IsDigit(r):
			digits++
		case !unicode.IsSpace(r):
			special++
		}
	}
	length := utf8.RuneCountInString(password)
	failed := []Rule{}
	for _, rule := range p.Rules() {
		ok := true
		switch rule.ID {
		case "length":
			ok = length >= p.MinLength && length <= MaxLength
		case "uppercase":
			ok = upper >= p.MinUppercase
		case "lowercase":
			ok = lower >= p.MinLowercase
		case "digits":
			ok = digits >= p.MinDigits
		case "special":
			ok = special >= p.MinSpecial
		case "common":
			ok = !p.isBlocked(password, avoid)
		}
		if !ok {
			failed = append(failed, rule)
		}
	}
	return failed
}

// isBlocked: on our list or the organisation's, also once trailing numbers
// and symbols are taken off ("Password1!" is "password"), or the same as
// something to avoid (the username, the organisation's name).
func (p Policy) isBlocked(password string, avoid []string) bool {
	lower := strings.ToLower(strings.TrimSpace(password))
	stem := strings.TrimRightFunc(lower, func(r rune) bool { return !unicode.IsLetter(r) })
	for _, candidate := range []string{lower, stem} {
		if candidate == "" {
			continue
		}
		if _, ok := common[candidate]; ok {
			return true
		}
		if slices.Contains(p.Blocked, candidate) {
			return true
		}
		for _, a := range avoid {
			if a = strings.ToLower(strings.TrimSpace(a)); len(a) >= 3 && candidate == a {
				return true
			}
		}
	}
	return false
}

// Message turns failed rules into one sentence for a form field.
func Message(failed []Rule) string {
	if len(failed) == 0 {
		return ""
	}
	var needs []string
	common := false
	for _, r := range failed {
		if r.ID == "common" {
			common = true
			continue
		}
		needs = append(needs, strings.ToLower(r.Label[:1])+r.Label[1:])
	}
	switch {
	case len(needs) == 0:
		return "That password is too easy to guess. Choose a different one."
	case common:
		return "Your password needs " + strings.Join(needs, ", ") + ", and can't be a commonly used password."
	default:
		return "Your password needs " + strings.Join(needs, ", ") + "."
	}
}
