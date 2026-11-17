package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// ── Deleting users, and bulk actions ─────────────────────────────────────
//
// Each bulk action is its own endpoint taking {userIds: [...]} and applies
// the same rules as changing one user: in this organisation, not a Keston
// support account, and someone the caller can change (canChange). It
// returns a result per user, done or skipped (with the reason), so Keston
// Admin can show a summary.

// maxBulk: users in one bulk request.
const maxBulk = 500

type bulkResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Result string `json:"result"` // "done" or "skipped"
	Reason string `json:"reason,omitempty"`
	// Reset passwords only: the new password, shown once.
	Password string `json:"password,omitempty"`
}

// userIDs reads {userIds}.
func userIDs(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var body struct {
		UserIDs []string `json:"userIds"`
	}
	if !decode(w, r, &body) {
		return nil, false
	}
	return body.UserIDs, checkIDs(w, body.UserIDs)
}

func checkIDs(w http.ResponseWriter, ids []string) bool {
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "Choose at least one user.")
		return false
	}
	if len(ids) > maxBulk {
		writeError(w, http.StatusBadRequest, "bad_request", "Choose up to 500 users at a time.")
		return false
	}
	return true
}

// bulkTargets returns, in order, a result for each ID with its user if
// they're someone the caller may change (nil and a skipped result
// otherwise). deleted: act on deleted users (restoring) rather than
// current ones.
func (a *API) bulkTargets(w http.ResponseWriter, r *http.Request, ids []string, deleted bool) ([]bulkResult,
	[]*store.User, bool) {
	ctx := r.Context()
	org := organisation(r)
	byID := map[string]*store.User{}
	if deleted {
		list, err := a.store.DeletedUsers(ctx, org.ID)
		if err != nil {
			serverError(w, r, err)
			return nil, nil, false
		}
		for i := range list {
			byID[list[i].ID] = &list[i].User
		}
	} else {
		list, err := a.store.UsersInOrganisation(ctx, org.ID)
		if err != nil {
			serverError(w, r, err)
			return nil, nil, false
		}
		for i := range list {
			byID[list[i].ID] = &list[i]
		}
	}
	perms, err := a.store.PermissionsInOrganisation(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return nil, nil, false
	}
	mine, admin := callerPerms(r), caller(r).Role == "global_admin"
	results := []bulkResult{}
	users := []*store.User{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		u := byID[id]
		res := bulkResult{ID: id, Result: "skipped"}
		switch {
		case u == nil:
			res.Reason = "Not found."
		case u.IsSupport():
			res.Reason = "Keston support accounts can't be changed here."
		case !admin && (u.Role == "global_admin" || !mine.Covers(perms[u.ID].List())):
			res.Reason = "Has permissions you don't, so you can't change them."
		default:
			res.Result = ""
		}
		if u != nil {
			res.Name, res.Email = u.Name, u.Email
		}
		if res.Result == "skipped" {
			u = nil
		}
		results = append(results, res)
		users = append(users, u)
	}
	return results, users, true
}

// runBulk applies do to each user that may be changed, and writes the
// results. do returns a reason to skip them ("" when done) or an error.
func (a *API) runBulk(w http.ResponseWriter, r *http.Request, ids []string, action string, deleted bool,
	do func(u *store.User, res *bulkResult) (string, error)) {
	results, users, ok := a.bulkTargets(w, r, ids, deleted)
	if !ok {
		return
	}
	done := 0
	for i, u := range users {
		if u == nil {
			continue
		}
		reason, err := do(u, &results[i])
		if err != nil {
			serverError(w, r, err)
			return
		}
		if reason != "" {
			results[i].Result, results[i].Reason = "skipped", reason
			continue
		}
		results[i].Result = "done"
		done++
	}
	slog.Info("bulk "+action, "organisation", organisation(r).ID, "done", done, "requested", len(results),
		"by", caller(r).ID)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// POST …/users/bulk/reset-password {userIds, password?, requirePasswordChange?}:
// without a password, each user gets their own new one (meeting the
// policy), returned once; with one, they all get that one (skipping anyone
// it doesn't suit, e.g. it's their username). requirePasswordChange
// defaults to on. They're unlocked and signed out everywhere.
func (a *API) bulkResetPassword(w http.ResponseWriter, r *http.Request) {
	pol := organisation(r).PasswordPolicy
	var body struct {
		UserIDs               []string `json:"userIds"`
		Password              string   `json:"password"`
		RequirePasswordChange *bool    `json:"requirePasswordChange"`
	}
	if !decode(w, r, &body) || !checkIDs(w, body.UserIDs) {
		return
	}
	mustChange := body.RequirePasswordChange == nil || *body.RequirePasswordChange
	if body.Password != "" {
		// The rules that don't depend on the user, checked once up front.
		if failed := pol.Check(body.Password, ""); len(failed) > 0 {
			writeFieldError(w, "password", policy.Message(failed))
			return
		}
	}
	a.runBulk(w, r, body.UserIDs, "password reset", false, func(u *store.User, res *bulkResult) (string, error) {
		username, _, _ := strings.Cut(u.Email, "@")
		username = normaliseUsername(username)
		pw := body.Password
		if pw == "" {
			pw = pol.Generate(username)
			res.Password = pw
		} else if failed := pol.Check(pw, username); len(failed) > 0 {
			return "The password doesn't suit them: " + policy.Message(failed), nil
		}
		if err := a.store.ResetPassword(r.Context(), u.ID, secret.HashPassword(pw)); err != nil {
			return "", err
		}
		if err := a.store.SetPasswordChangeRequired(r.Context(), u.ID, mustChange); err != nil {
			return "", err
		}
		summary := "Bulk action"
		if body.Password != "" {
			summary = "Bulk action, the same password for everyone"
		}
		a.audit(r, store.ActionUserPasswordReset, aboutUser(u), summary)
		return "", nil
	})
}

func (a *API) bulkStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids, ok := userIDs(w, r)
		if !ok {
			return
		}
		a.runBulk(w, r, ids, "status "+status, false, func(u *store.User, _ *bulkResult) (string, error) {
			if status == "disabled" && u.ID == caller(r).ID {
				return "You can't disable yourself.", nil
			}
			if u.Status == status {
				return map[string]string{"active": "Already enabled.", "disabled": "Already disabled."}[status], nil
			}
			if err := a.store.SetUserStatus(r.Context(), u.ID, status); err != nil {
				return "", err
			}
			action := store.ActionUserEnabled
			if status == "disabled" {
				action = store.ActionUserDisabled
			}
			a.audit(r, action, aboutUser(u), change("Status", statusLabel(u.Status), statusLabel(status))+" (bulk action)")
			return "", nil
		})
	}
}

// POST …/users/bulk/disable and …/enable
func (a *API) bulkDisable(w http.ResponseWriter, r *http.Request) { a.bulkStatus("disabled")(w, r) }
func (a *API) bulkEnable(w http.ResponseWriter, r *http.Request)  { a.bulkStatus("active")(w, r) }

// bulkGroup: POST …/users/bulk/add-to-group and …/remove-from-group
// {groupId, userIds}. The group must be one the caller may change who's in
// (mayChangeGroup), as for one user.
func (a *API) bulkGroup(add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GroupID string   `json:"groupId"`
			UserIDs []string `json:"userIds"`
		}
		if !decode(w, r, &body) || !checkIDs(w, body.UserIDs) {
			return
		}
		g, err := a.store.Group(r.Context(), organisation(r).ID, body.GroupID)
		if err != nil {
			writeFieldError(w, "groupId", "Choose a group")
			return
		}
		if !mayChangeGroup(w, r, g) {
			return
		}
		in := map[string]bool{}
		members, err := a.store.GroupMembers(r.Context(), g.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		for _, m := range members {
			in[m.ID] = true
		}
		action := "remove from group"
		if add {
			action = "add to group"
		}
		a.runBulk(w, r, body.UserIDs, action, false, func(u *store.User, res *bulkResult) (string, error) {
			if add {
				if in[u.ID] {
					return "Already in " + g.Name + ".", nil
				}
				if err := a.store.AddGroupMember(r.Context(), g.ID, u.ID); err != nil {
					return "", err
				}
				a.audit(r, store.ActionGroupMemberAdded, aboutUser(u), "Group: "+g.Name)
				res.Reason = a.notLicensedNote(r, u)
				return "", nil
			}
			if !in[u.ID] {
				return "Not in " + g.Name + ".", nil
			}
			if err := a.store.RemoveGroupMember(r.Context(), g.ID, u.ID); err != nil {
				return "", err
			}
			a.audit(r, store.ActionGroupMemberRemoved, aboutUser(u), "Group: "+g.Name)
			return "", nil
		})
	}
}

// POST …/users/bulk/groups {userIds, add: [groupId], remove: [groupId]}:
// adds everyone to some groups and takes them out of others, in one go.
// Each group must be one the caller may change who's in (mayChangeGroup).
func (a *API) bulkGroups(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserIDs []string `json:"userIds"`
		Add     []string `json:"add"`
		Remove  []string `json:"remove"`
	}
	if !decode(w, r, &body) || !checkIDs(w, body.UserIDs) {
		return
	}
	if len(body.Add)+len(body.Remove) == 0 {
		writeFieldError(w, "add", "Choose at least one group")
		return
	}
	ctx := r.Context()
	load := func(ids []string, field string) ([]*store.Group, bool) {
		out := []*store.Group{}
		for _, id := range ids {
			g, err := a.store.Group(ctx, organisation(r).ID, id)
			if err != nil {
				writeFieldError(w, field, "Choose from your groups")
				return nil, false
			}
			if !mayChangeGroup(w, r, g) {
				return nil, false
			}
			out = append(out, g)
		}
		return out, true
	}
	add, ok := load(body.Add, "add")
	if !ok {
		return
	}
	remove, ok := load(body.Remove, "remove")
	if !ok {
		return
	}
	for _, g := range add {
		for _, h := range remove {
			if g.ID == h.ID {
				writeFieldError(w, "remove", g.Name+" is in both lists")
				return
			}
		}
	}
	members := map[string]map[string]bool{}
	for _, g := range append(append([]*store.Group{}, add...), remove...) {
		list, err := a.store.GroupMembers(ctx, g.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		members[g.ID] = map[string]bool{}
		for _, m := range list {
			members[g.ID][m.ID] = true
		}
	}
	a.runBulk(w, r, body.UserIDs, "group memberships", false, func(u *store.User, res *bulkResult) (string, error) {
		changed, joined := false, false
		for _, g := range add {
			if members[g.ID][u.ID] {
				continue
			}
			if err := a.store.AddGroupMember(ctx, g.ID, u.ID); err != nil {
				return "", err
			}
			a.audit(r, store.ActionGroupMemberAdded, aboutUser(u), "Group: "+g.Name)
			changed, joined = true, true
		}
		for _, g := range remove {
			if !members[g.ID][u.ID] {
				continue
			}
			if err := a.store.RemoveGroupMember(ctx, g.ID, u.ID); err != nil {
				return "", err
			}
			a.audit(r, store.ActionGroupMemberRemoved, aboutUser(u), "Group: "+g.Name)
			changed = true
		}
		if !changed {
			return "Already in or out of those groups.", nil
		}
		if joined {
			res.Reason = a.notLicensedNote(r, u)
		}
		return "", nil
	})
}

func (a *API) bulkAddToGroup(w http.ResponseWriter, r *http.Request)      { a.bulkGroup(true)(w, r) }
func (a *API) bulkRemoveFromGroup(w http.ResponseWriter, r *http.Request) { a.bulkGroup(false)(w, r) }

// deleteOne deletes someone the caller may change, or says why not.
func (a *API) deleteOne(r *http.Request, u *store.User) (string, error) {
	if u.ID == caller(r).ID {
		return "You can't delete yourself.", nil
	}
	err := a.store.DeleteUser(r.Context(), organisation(r).ID, u.ID, caller(r).ID)
	switch {
	case errors.Is(err, store.ErrLastGlobalAdmin):
		return "They're the last global admin.", nil
	case errors.Is(err, store.ErrNotFound):
		return "Not found.", nil
	case err != nil:
		return "", err
	}
	slog.Info("user deleted", "user", u.ID, "organisation", organisation(r).ID, "by", caller(r).ID)
	a.audit(r, store.ActionUserDeleted, aboutUser(u), "Can be restored for 30 days")
	return "", nil
}

// POST …/users/bulk/delete
func (a *API) bulkDelete(w http.ResponseWriter, r *http.Request) {
	ids, ok := userIDs(w, r)
	if !ok {
		return
	}
	a.runBulk(w, r, ids, "delete", false, func(u *store.User, _ *bulkResult) (string, error) { return a.deleteOne(r, u) })
}

// DELETE …/users/{id}: one user, kept 30 days in Deleted users.
func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	reason, err := a.deleteOne(r, u)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if reason != "" {
		writeError(w, http.StatusConflict, "cant_delete", reason)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET …/deleted-users: users deleted in the last 30 days.
func (a *API) listDeletedUsers(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.DeletedUsers(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	perms, err := a.store.PermissionsInOrganisation(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	type row struct {
		userJSON
		DeletedAt     time.Time `json:"deletedAt"`
		PurgeAfter    time.Time `json:"purgeAfter"`
		DeletedByName *string   `json:"deletedByName,omitempty"`
		CanChange     bool      `json:"canChange"`
	}
	mine, admin := callerPerms(r), caller(r).Role == "global_admin"
	out := make([]row, len(list))
	for i := range list {
		d := &list[i]
		can := admin || (d.Role != "global_admin" && mine.Covers(perms[d.ID].List()))
		out[i] = row{a.userView(&d.User), d.DeletedAt, d.PurgeAfter, d.DeletedByName, can}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST …/deleted-users/restore {userIds}: back as they were, with their
// groups.
func (a *API) bulkRestore(w http.ResponseWriter, r *http.Request) {
	ids, ok := userIDs(w, r)
	if !ok {
		return
	}
	a.runBulk(w, r, ids, "restore", true, func(u *store.User, _ *bulkResult) (string, error) {
		err := a.store.RestoreUser(r.Context(), organisation(r).ID, u.ID)
		if errors.Is(err, store.ErrNotFound) {
			return "Not found.", nil
		}
		if err == nil {
			a.audit(r, store.ActionUserRestored, aboutUser(u), "")
		}
		return "", err
	})
}

// maxBulkCreate: users added in one go.
const maxBulkCreate = 250

// POST …/users/bulk/create {users: [{name, username, domain?}], password?,
// licences, requirePasswordChange?}: adds members with the same licences.
// Each gets their own new password (returned once), or all get the one
// given (e.g. for a new school year, changed at first sign-in). A domain
// must be one of the organisation's (the main one if left out). A row that
// can't be added (no name, a username that's taken…) is skipped with the
// reason; the rest are still added. requirePasswordChange defaults to on.
func (a *API) bulkCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Users []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Domain   string `json:"domain"`
		} `json:"users"`
		Password              string   `json:"password"`
		Licences              []string `json:"licences"`
		RequirePasswordChange *bool    `json:"requirePasswordChange"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Users) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "Add at least one user.")
		return
	}
	if len(body.Users) > maxBulkCreate {
		writeError(w, http.StatusBadRequest, "bad_request", "Add up to 250 users at a time.")
		return
	}
	if !a.checkProducts(w, r, body.Licences) {
		return
	}
	ctx := r.Context()
	org := organisation(r)
	if body.Password != "" {
		if failed := org.PasswordPolicy.Check(body.Password); len(failed) > 0 {
			writeFieldError(w, "password", policy.Message(failed))
			return
		}
	}
	domains := orgDomains(org)
	mustChange := body.RequirePasswordChange == nil || *body.RequirePasswordChange
	results := make([]bulkResult, len(body.Users))
	seen := map[string]bool{}
	done := 0
	for i, in := range body.Users {
		name := strings.TrimSpace(in.Name)
		username := normaliseUsername(in.Username)
		domain := strings.ToLower(strings.TrimSpace(in.Domain))
		if domain == "" {
			domain = org.Domain
		}
		email := username + "@" + domain
		res := bulkResult{Name: name, Email: email, Result: "skipped"}
		switch {
		case name == "" || len(name) > 200:
			res.Reason = "Enter their name."
		case !usernameRE.MatchString(username):
			res.Reason = usernameHelp
		case !slices.Contains(domains, domain):
			res.Reason = domain + " isn't one of your domains."
		case seen[email]:
			res.Reason = "The same email is in the list twice."
		}
		seen[email] = true
		if res.Reason != "" {
			results[i] = res
			continue
		}
		pw := body.Password
		if pw == "" {
			pw = org.PasswordPolicy.Generate(username)
		} else if failed := org.PasswordPolicy.Check(pw, username); len(failed) > 0 {
			res.Reason = "The password doesn't suit them: " + policy.Message(failed)
			results[i] = res
			continue
		}
		if len(body.Licences) > 0 {
			var noSeats *store.NoSeatsError
			err := a.store.CheckSeats(ctx, org.ID, body.Licences, 1)
			if errors.As(err, &noSeats) {
				res.Reason = "No " + strings.Join(noSeats.Names, ", ") + " licences left."
				results[i] = res
				continue
			}
			if err != nil {
				serverError(w, r, err)
				return
			}
		}
		created, err := a.store.CreateUser(ctx, a.store.DB, store.NewUser{
			OrganisationID: org.ID, Email: email, Name: name, Role: "member", PasswordHash: secret.HashPassword(pw),
		})
		if isUniqueViolation(err) {
			res.Reason = email + " already exists."
			if existing, _ := a.store.UserByEmail(ctx, email); existing != nil && existing.Status == "deleted" {
				res.Reason = email + " was deleted recently. Restore them from Deleted users instead."
			}
			results[i] = res
			continue
		}
		if err != nil {
			serverError(w, r, err)
			return
		}
		if mustChange {
			if err := a.store.SetPasswordChangeRequired(ctx, created.ID, true); err != nil {
				serverError(w, r, err)
				return
			}
		}
		a.audit(r, store.ActionUserCreated, aboutUser(created), "Role: Member (added with others)")
		if len(body.Licences) > 0 {
			err := a.applyLicences(r, created, body.Licences)
			var noSeats *store.NoSeatsError
			if errors.As(err, &noSeats) {
				// Someone took the last seat meanwhile: added, but without it.
				res.Reason = "Added without a licence: no " + strings.Join(noSeats.Names, ", ") + " licences left."
			} else if err != nil {
				serverError(w, r, err)
				return
			}
		}
		res.ID, res.Result = created.ID, "done"
		if body.Password == "" {
			res.Password = pw
		}
		results[i] = res
		done++
	}
	slog.Info("bulk create", "organisation", org.ID, "done", done, "requested", len(body.Users), "by", caller(r).ID)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// orgDomains: the domains an organisation's users can have (one, for now).
func orgDomains(org *store.Organisation) []string { return []string{strings.ToLower(org.Domain)} }
