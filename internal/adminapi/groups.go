package adminapi

import (
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// ── Groups ───────────────────────────────────────────────────────────────

// GET …/groups?q=&members=gt:12&permissions=yes|no&sort=&dir=: the groups.
//
//	q            part of the name
//	members      a comparison and a number: gt:12 (more than 12), gte, lt, lte, eq
//	permissions  yes: gives permissions in Keston Admin; no: gives none
//	sort         name | members | permissions | created (default name)
//	dir          asc | desc (default asc)
func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.GroupFilter{Q: strings.TrimSpace(q.Get("q")), Sort: q.Get("sort"), Desc: q.Get("dir") == "desc"}
	if v := q.Get("members"); v != "" {
		op, n, ok := strings.Cut(v, ":")
		count, err := strconv.Atoi(n)
		if !ok || !store.IsMemberOp(op) || err != nil || count < 0 {
			writeFieldError(w, "members", "Use a comparison and a number, like gt:12")
			return
		}
		f.Members = &store.MemberCount{Op: op, N: count}
	}
	switch q.Get("permissions") {
	case "":
	case "yes", "no":
		yes := q.Get("permissions") == "yes"
		f.Permissions = &yes
	default:
		writeFieldError(w, "permissions", "Choose yes or no")
		return
	}
	if f.Sort == "" {
		f.Sort = "name"
	}
	if !slices.Contains(store.GroupSorts, f.Sort) {
		writeFieldError(w, "sort", "Sort by name, members, permissions or created")
		return
	}
	if d := q.Get("dir"); d != "" && d != "asc" && d != "desc" {
		writeFieldError(w, "dir", "Choose asc or desc")
		return
	}
	groups, err := a.store.GroupsFiltered(r.Context(), organisation(r).ID, f)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func groupName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return "", false
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		writeFieldError(w, "name", "Enter a name for the group")
		return "", false
	}
	return name, true
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	name, ok := groupName(w, r)
	if !ok {
		return
	}
	g, err := a.store.CreateGroup(r.Context(), organisation(r).ID, name)
	if isUniqueViolation(err) {
		writeFieldError(w, "name", "There's already a group called "+name)
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionGroupCreated, aboutGroup(g), "")
	writeJSON(w, http.StatusCreated, g)
}

// group is the group in the URL, in this organisation.
func (a *API) group(w http.ResponseWriter, r *http.Request) *store.Group {
	g, err := a.store.Group(r.Context(), organisation(r).ID, chi.URLParam(r, "groupID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "That group doesn't exist.")
		return nil
	}
	return g
}

// GET …/groups/{id}: the group and its members.
func (a *API) getGroup(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	members, err := a.store.GroupMembers(r.Context(), g.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	passkeys, err := a.store.PasskeyCounts(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]userJSON, len(members))
	for i := range members {
		out[i] = withPasskeys(a.userView(&members[i]), passkeys[members[i].ID])
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": g, "members": out})
}

func (a *API) renameGroup(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	name, ok := groupName(w, r)
	if !ok {
		return
	}
	err := a.store.RenameGroup(r.Context(), organisation(r).ID, g.ID, name)
	if isUniqueViolation(err) {
		writeFieldError(w, "name", "There's already a group called "+name)
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionGroupRenamed, about{store.TargetGroup, g.ID, name}, change("Name", g.Name, name))
	w.WriteHeader(http.StatusNoContent)
}

// mayChangeGroup: changing a group's members (or deleting it) needs Manage
// groups; for a group that gives permissions, Give permissions and every
// one of its permissions too, so nobody can hand out more than they have.
func mayChangeGroup(w http.ResponseWriter, r *http.Request, g *store.Group) bool {
	if msg := groupChangeProblem(r, g); msg != "" {
		writeError(w, http.StatusForbidden, "no_permission", msg)
		return false
	}
	return true
}

// groupChangeProblem is why the caller can't change who's in g ("": they can).
func groupChangeProblem(r *http.Request, g *store.Group) string {
	if len(g.Permissions) == 0 {
		if can(r, store.PermGroups) || can(r, store.PermAssign) {
			return ""
		}
		return "You don't have permission to do that. Ask one of your global admins."
	}
	if can(r, store.PermAssign) && permsIn(r, organisation(r).ID).Covers(g.Permissions) {
		return ""
	}
	return g.Name + " gives permissions you don't have, so you can't change who's in it. Ask one of your global admins."
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil || !mayChangeGroup(w, r, g) {
		return
	}
	if err := a.store.DeleteGroup(r.Context(), organisation(r).ID, g.ID); err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionGroupDeleted, aboutGroup(g), "")
	w.WriteHeader(http.StatusNoContent)
}

// member is the user in the URL, for adding to or removing from a group:
// in this organisation, not a support account, and someone the caller can
// change.
func (a *API) member(w http.ResponseWriter, r *http.Request) *store.User {
	u, err := a.store.UserByID(r.Context(), chi.URLParam(r, "userID"))
	// Their own people, or accepted guests (groups are the one thing a guest
	// organisation sets for them besides roles).
	if err != nil || u.IsSupport() || u.Status == "deleted" ||
		(u.OrganisationID != organisation(r).ID && !a.store.IsGuestIn(r.Context(), u.ID, organisation(r).ID)) {
		writeError(w, http.StatusNotFound, "not_found", "That user doesn't exist.")
		return nil
	}
	ok, err := a.canChange(r, u)
	if err != nil {
		serverError(w, r, err)
		return nil
	}
	if !ok {
		outranked(w, u)
		return nil
	}
	return u
}

func (a *API) addMember(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil || !mayChangeGroup(w, r, g) {
		return
	}
	u := a.member(w, r)
	if u == nil {
		return
	}
	if err := a.store.AddGroupMember(r.Context(), g.ID, u.ID); err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionGroupMemberAdded, aboutUser(u), "Group: "+g.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) removeMember(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil || !mayChangeGroup(w, r, g) {
		return
	}
	u := a.member(w, r)
	if u == nil {
		return
	}
	if err := a.store.RemoveGroupMember(r.Context(), g.ID, u.ID); err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionGroupMemberRemoved, aboutUser(u), "Group: "+g.Name)
	w.WriteHeader(http.StatusNoContent)
}

// PUT …/groups/{id}/permissions {permissions: [...]}: what the group's users
// can do in Keston Admin. Only up to the caller's own permissions, and only
// for a group whose current permissions they all have.
func (a *API) putGroupPermissions(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if !decode(w, r, &body) {
		return
	}
	perms := store.CleanPermissions(body.Permissions)
	mine := permsIn(r, organisation(r).ID)
	if !mine.Covers(g.Permissions) {
		writeError(w, http.StatusForbidden, "no_permission",
			g.Name+" already gives permissions you don't have, so you can't change them. Ask one of your global admins.")
		return
	}
	if !mine.Covers(perms) {
		writeError(w, http.StatusForbidden, "no_permission", "You can only give permissions you have yourself.")
		return
	}
	if err := a.store.SetGroupPermissions(r.Context(), g.ID, perms); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("group permissions changed", "group", g.ID, "permissions", perms, "by", caller(r).ID)
	a.audit(r, store.ActionGroupPermissions, aboutGroup(g), change("Permissions", permLabels(g.Permissions),
		permLabels(perms)))
	updated, _ := a.store.Group(r.Context(), organisation(r).ID, g.ID)
	writeJSON(w, http.StatusOK, updated)
}

// ── Bulk: change the members of several groups ───────────────────────────

// groupResult is what happened to one group in POST …/groups/bulk/members.
type groupResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Result string `json:"result"` // "done" or "skipped"
	Reason string `json:"reason,omitempty"`
	// Who joined and who left (only those who weren't already in or out).
	Added   []memberRef `json:"added"`
	Removed []memberRef `json:"removed"`
	// Members after the change.
	MemberCount int `json:"memberCount"`
}

type memberRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// POST …/groups/bulk/members {groupIds, add: [userId], remove: [userId]}:
// adds the users in add to every one of the groups and takes the users in
// remove out of them. Each group must be one the caller may change who's in
// (groupChangeProblem), and each user someone they may change (as for one
// user: in this organisation, not a support account, canChange); anything
// else is skipped with the reason, not failed. Each membership change is
// recorded in the admin log, as when done one at a time. Returns {groups:
// [groupResult], skippedUsers: [bulkResult]} for the summary.
func (a *API) bulkGroupMembers(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupIDs []string `json:"groupIds"`
		Add      []string `json:"add"`
		Remove   []string `json:"remove"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch {
	case len(body.GroupIDs) == 0:
		writeError(w, http.StatusBadRequest, "bad_request", "Choose at least one group.")
		return
	case len(body.GroupIDs) > maxBulk || len(body.Add) > maxBulk || len(body.Remove) > maxBulk:
		writeError(w, http.StatusBadRequest, "bad_request", "Choose up to 500 groups or users at a time.")
		return
	case len(body.Add)+len(body.Remove) == 0:
		writeFieldError(w, "add", "Choose at least one user")
		return
	}
	for _, id := range body.Add {
		if slices.Contains(body.Remove, id) {
			writeFieldError(w, "remove", "Someone is in both lists")
			return
		}
	}
	ctx := r.Context()
	org := organisation(r)

	// Who can be changed, once for all the groups.
	skipped := []bulkResult{}
	loadUsers := func(ids []string) []*store.User {
		out := []*store.User{}
		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			res := bulkResult{ID: id, Result: "skipped"}
			u, err := a.store.UserByID(ctx, id)
			switch {
			case err != nil || u.OrganisationID != org.ID || u.Status == "deleted":
				res.Reason = "Not found."
			case u.IsSupport():
				res.Name, res.Email = u.Name, u.Email
				res.Reason = "Keston support accounts can't be changed here."
			default:
				res.Name, res.Email = u.Name, u.Email
				ok, err := a.canChange(r, u)
				if err != nil {
					serverError(w, r, err)
					return nil
				}
				if ok {
					out = append(out, u)
					continue
				}
				res.Reason = "Has permissions you don't, so you can't change them."
			}
			skipped = append(skipped, res)
		}
		return out
	}
	add := loadUsers(body.Add)
	remove := loadUsers(body.Remove)
	if add == nil || remove == nil {
		return // an error was written
	}

	results := []groupResult{}
	seen := map[string]bool{}
	changed := 0
	for _, id := range body.GroupIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		res := groupResult{ID: id, Result: "skipped", Added: []memberRef{}, Removed: []memberRef{}}
		g, err := a.store.Group(ctx, org.ID, id)
		if err != nil {
			res.Reason = "Not found."
			results = append(results, res)
			continue
		}
		res.Name, res.MemberCount = g.Name, g.MemberCount
		if msg := groupChangeProblem(r, g); msg != "" {
			res.Reason = msg
			results = append(results, res)
			continue
		}
		list, err := a.store.GroupMembers(ctx, g.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		in := map[string]bool{}
		for _, m := range list {
			in[m.ID] = true
		}
		for _, u := range add {
			if in[u.ID] {
				continue
			}
			if err := a.store.AddGroupMember(ctx, g.ID, u.ID); err != nil {
				serverError(w, r, err)
				return
			}
			a.audit(r, store.ActionGroupMemberAdded, aboutUser(u), "Group: "+g.Name)
			res.Added = append(res.Added, memberRef{u.ID, u.Name, u.Email})
		}
		for _, u := range remove {
			if !in[u.ID] {
				continue
			}
			if err := a.store.RemoveGroupMember(ctx, g.ID, u.ID); err != nil {
				serverError(w, r, err)
				return
			}
			a.audit(r, store.ActionGroupMemberRemoved, aboutUser(u), "Group: "+g.Name)
			res.Removed = append(res.Removed, memberRef{u.ID, u.Name, u.Email})
		}
		res.MemberCount += len(res.Added) - len(res.Removed)
		if len(res.Added)+len(res.Removed) == 0 {
			res.Reason = "Already up to date."
		} else {
			res.Result = "done"
			changed++
		}
		results = append(results, res)
	}
	slog.Info("bulk group members", "organisation", org.ID, "groups", len(results), "changed", changed, "by", caller(r).ID)
	writeJSON(w, http.StatusOK, map[string]any{"groups": results, "skippedUsers": skipped})
}
