package adminapi

import (
	"github.com/thekestongroup/id/internal/clientip"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/store"
)

// ── Recording admin actions ──────────────────────────────────────────────

// about is what an action was done to.
type about struct{ typ, id, name string }

func aboutUser(u *store.User) about        { return about{store.TargetUser, u.ID, u.Name} }
func aboutGroup(g *store.Group) about      { return about{store.TargetGroup, g.ID, g.Name} }
func aboutApp(c *store.Client) about       { return about{store.TargetApp, c.ID, c.Name} }
func aboutOrg(o *store.Organisation) about { return about{store.TargetOrganisation, o.ID, o.Name} }

// audit records what the caller just did in the organisation in the URL.
func (a *API) audit(r *http.Request, action string, t about, summary string) {
	a.auditIn(r, organisation(r).ID, action, t, summary)
}

func (a *API) auditIn(r *http.Request, orgID, action string, t about, summary string) {
	a.store.Audit(r.Context(), store.AuditEntry{OrganisationID: orgID, Actor: caller(r), Action: action,
		TargetType: t.typ, TargetID: t.id, TargetName: t.name, Summary: summary, IP: clientip.From(r)})
}

// change is "Label: before → after", or "" if it didn't change.
func change(label, before, after string) string {
	if before == after {
		return ""
	}
	if before == "" {
		before = "none"
	}
	if after == "" {
		after = "none"
	}
	return label + ": " + before + " → " + after
}

// summary joins the parts that aren't empty.
func summary(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), "; ")
}

func roleLabel(role string) string {
	if role == "global_admin" {
		return "Global admin"
	}
	return "Member"
}

func onOff(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

// permLabels: permissions by their labels, in catalogue order.
func permLabels(ids []string) string {
	out := []string{}
	for _, p := range store.Permissions {
		if slices.Contains(ids, p.ID) {
			out = append(out, p.Label)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

// ── Reading the logs ─────────────────────────────────────────────────────

// listParam reads a parameter that can name several values, repeated
// (?user=a&user=b) or comma-separated (?user=a,b). Empty values are dropped
// and duplicates are removed.
func listParam(q url.Values, name string) []string {
	out := []string{}
	for _, v := range q[name] {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" && !slices.Contains(out, part) {
				out = append(out, part)
			}
		}
	}
	return out
}

// maxFilterValues: values of one multi-value filter (users, reasons, …).
const maxFilterValues = 100

// logFilter reads the filters both logs share: user (one or more), from, to
// (dates, or times), before (paging) and limit.
func logFilter(w http.ResponseWriter, r *http.Request) (store.LogFilter, bool) {
	q := r.URL.Query()
	f := store.LogFilter{OrganisationID: organisation(r).ID, UserIDs: listParam(q, "user")}
	if len(f.UserIDs) > maxFilterValues {
		writeFieldError(w, "user", "Choose up to 100 users.")
		return f, false
	}
	for _, id := range f.UserIDs {
		if !store.IsUUID(id) {
			writeFieldError(w, "user", "That user doesn't exist.")
			return f, false
		}
	}
	for _, p := range []struct {
		name string
		dst  **time.Time
		end  bool
	}{{"from", &f.From, false}, {"to", &f.To, true}} {
		v := q.Get(p.name)
		if v == "" {
			continue
		}
		t, err := parseWhen(v, p.end)
		if err != nil {
			writeFieldError(w, p.name, "Enter a date like 2026-11-15")
			return f, false
		}
		*p.dst = &t
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			writeFieldError(w, "before", "That page doesn't exist.")
			return f, false
		}
		f.Before = n
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	return f, true
}

// parseWhen reads a date (2026-11-15: from the start of that day, or for
// "to", up to the end of it) or a time (RFC 3339).
func parseWhen(v string, end bool) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.DateOnly, v)
	if err != nil {
		return t, err
	}
	if end {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

// page is one page of a log; next is the "before" for the next page.
func page[T any](entries []T, next int64) map[string]any {
	if entries == nil {
		entries = []T{}
	}
	var n *string
	if next > 0 {
		s := strconv.FormatInt(next, 10)
		n = &s
	}
	return map[string]any{"entries": entries, "next": n}
}

// GET …/audit-log?user=a&user=b&action=a,b&from=&to=&before=&limit=: what admins
// did here, newest first.
func (a *API) auditLog(w http.ResponseWriter, r *http.Request) {
	f, ok := logFilter(w, r)
	if !ok {
		return
	}
	f.Actions = listParam(r.URL.Query(), "action")
	entries, next, err := a.store.AuditLog(r.Context(), f)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(entries, next))
}

// GET …/sign-ins?user=a&user=b&result=success|failure&reason=a&reason=b&from=&to=&before=&limit=:
// sign-in attempts here, newest first.
func (a *API) signIns(w http.ResponseWriter, r *http.Request) {
	f, ok := logFilter(w, r)
	if !ok {
		return
	}
	switch r.URL.Query().Get("result") {
	case "success":
		f.Success = new(bool)
		*f.Success = true
	case "failure":
		f.Success = new(bool)
	}
	f.Reasons = listParam(r.URL.Query(), "reason")
	if len(f.Reasons) > maxFilterValues {
		writeFieldError(w, "reason", "Choose up to 100 reasons.")
		return
	}
	entries, next, err := a.store.SignIns(r.Context(), f)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page(entries, next))
}

func statusLabel(s string) string {
	if s == "disabled" {
		return "Disabled"
	}
	return "Active"
}

// modeLabel: an app access setting ("" is none: the default applies).
func modeLabel(m string) string {
	switch m {
	case store.AppForced:
		return "Forced"
	case store.AppEnabled:
		return "Enabled"
	case store.AppDisabled:
		return "Disabled"
	}
	return "Default"
}

// policyChanges: what changed in a password policy.
func policyChanges(before, after policy.Policy) string {
	n := strconv.Itoa
	blocked := func(p policy.Policy) string { return strconv.Itoa(len(p.Blocked)) + " banned" }
	return summary(
		change("Minimum length", n(before.MinLength), n(after.MinLength)),
		change("Uppercase letters", n(before.MinUppercase), n(after.MinUppercase)),
		change("Lowercase letters", n(before.MinLowercase), n(after.MinLowercase)),
		change("Numbers", n(before.MinDigits), n(after.MinDigits)),
		change("Symbols", n(before.MinSpecial), n(after.MinSpecial)),
		change("Banned passwords", blocked(before), blocked(after)),
	)
}
