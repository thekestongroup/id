package adminapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/thekestongroup/id/internal/store"
)

// userRow is one user in GET …/users.
type userRow struct {
	userJSON
	// The caller can change them (see canChange).
	CanChange bool `json:"canChange"`
	// The products they have a licence for.
	Licences []string `json:"licences"`
	// Their admin roles (besides global admin).
	Roles []string `json:"roles"`
	// The groups they're in (only filled in when filtering by group).
	groups  []string
	created time.Time
}

// userFilter is what GET …/users?… asks for. Every filter is optional; the
// values of one filter are alternatives (role=user,global_admin is either),
// and different filters all have to match.
//
//	q        part of their name or email
//	role     user | global_admin | tkg_admin | an admin role's ID
//	status   active | disabled | locked
//	licence  a product's ID, or "none" for nobody-licensed
//	group    a group's ID
//	mfa      on | off
//	sort     name | email | role | status | created (default name)
//	dir      asc | desc (default asc)
type userFilter struct {
	q                string
	roles, statuses  []string
	licences, groups []string
	mfa              string
	sort             string
	desc             bool
}

var (
	userStatuses = []string{"active", "disabled", "locked"}
	userSorts    = []string{"name", "email", "role", "status", "created"}
)

func userFilterFrom(w http.ResponseWriter, r *http.Request) (userFilter, bool) {
	q := r.URL.Query()
	f := userFilter{q: strings.ToLower(strings.TrimSpace(q.Get("q"))), roles: listParam(q, "role"),
		statuses: listParam(q, "status"), licences: listParam(q, "licence"), groups: listParam(q, "group"),
		mfa: q.Get("mfa"), sort: q.Get("sort"), desc: q.Get("dir") == "desc"}
	bad := func(field, msg string) (userFilter, bool) {
		writeFieldError(w, field, msg)
		return f, false
	}
	for _, v := range f.statuses {
		if !slices.Contains(userStatuses, v) {
			return bad("status", "Choose active, disabled or locked")
		}
	}
	for _, v := range f.groups {
		if !store.IsUUID(v) {
			return bad("group", "That group doesn't exist.")
		}
	}
	if len(f.roles) > maxFilterValues || len(f.licences) > maxFilterValues || len(f.groups) > maxFilterValues {
		return bad("filter", "Choose up to 100 values for a filter.")
	}
	if f.mfa != "" && f.mfa != "on" && f.mfa != "off" {
		return bad("mfa", "Choose on or off")
	}
	if f.sort == "" {
		f.sort = "name"
	}
	if !slices.Contains(userSorts, f.sort) {
		return bad("sort", "Sort by name, email, role, status or created")
	}
	if d := q.Get("dir"); d != "" && d != "asc" && d != "desc" {
		return bad("dir", "Choose asc or desc")
	}
	return f, true
}

// roleKind: how a user is shown in the Role filter and column.
func (u userRow) roleKinds() []string {
	switch {
	case u.Role == "global_admin" && u.PlatformAdmin:
		return []string{"tkg_admin"}
	case u.Role == "global_admin":
		return []string{"global_admin"}
	case len(u.Roles) > 0:
		return u.Roles
	}
	return []string{"user"}
}

// roleRank orders the Role column: users, then admin roles, global admins, TKG admins.
func (u userRow) roleRank() int {
	switch {
	case u.Role == "global_admin" && u.PlatformAdmin:
		return 3
	case u.Role == "global_admin":
		return 2
	case len(u.Roles) > 0:
		return 1
	}
	return 0
}

func (u userRow) state() string {
	switch {
	case u.Status == "disabled":
		return "disabled"
	case u.Locked:
		return "locked"
	}
	return "active"
}

func (u userRow) matches(f userFilter) bool {
	if f.q != "" && !strings.Contains(strings.ToLower(u.Name), f.q) && !strings.Contains(strings.ToLower(u.Email), f.q) {
		return false
	}
	if len(f.roles) > 0 && !slices.ContainsFunc(u.roleKinds(), func(k string) bool { return slices.Contains(f.roles, k) }) {
		return false
	}
	if len(f.statuses) > 0 && !slices.Contains(f.statuses, u.state()) {
		return false
	}
	if len(f.licences) > 0 {
		hit := slices.ContainsFunc(u.Licences, func(l string) bool { return slices.Contains(f.licences, l) }) ||
			(len(u.Licences) == 0 && slices.Contains(f.licences, "none"))
		if !hit {
			return false
		}
	}
	if len(f.groups) > 0 && !slices.ContainsFunc(u.groups, func(g string) bool { return slices.Contains(f.groups, g) }) {
		return false
	}
	switch f.mfa {
	case "on":
		return u.MFA
	case "off":
		return !u.MFA
	}
	return true
}

// apply filters and sorts the users. Ties are broken by name, then email.
func (f userFilter) apply(rows []userRow) []userRow {
	out := make([]userRow, 0, len(rows))
	for _, u := range rows {
		if u.matches(f) {
			out = append(out, u)
		}
	}
	rank := map[string]int{"active": 0, "locked": 1, "disabled": 2}
	cmp := func(a, b userRow) int {
		switch f.sort {
		case "email":
			return strings.Compare(strings.ToLower(a.Email), strings.ToLower(b.Email))
		case "role":
			return a.roleRank() - b.roleRank()
		case "status":
			return rank[a.state()] - rank[b.state()]
		case "created":
			return a.created.Compare(b.created)
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	}
	slices.SortStableFunc(out, func(a, b userRow) int {
		c := cmp(a, b)
		if f.desc {
			c = -c
		}
		if c != 0 {
			return c
		}
		if c = strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Email, b.Email)
	})
	return out
}
