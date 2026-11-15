package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

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

// POST …/users/bulk/reset-password: each user gets their own new password
// (meeting the policy), returned once. They're unlocked and signed out
// everywhere.
func (a *API) bulkResetPassword(w http.ResponseWriter, r *http.Request) {
	pol := organisation(r).PasswordPolicy
	ids, ok := userIDs(w, r)
	if !ok {
		return
	}
	a.runBulk(w, r, ids, "password reset", false, func(u *store.User, res *bulkResult) (string, error) {
		username, _, _ := strings.Cut(u.Email, "@")
		pw := pol.Generate(normaliseUsername(username))
		if err := a.store.ResetPassword(r.Context(), u.ID, secret.HashPassword(pw)); err != nil {
			return "", err
		}
		res.Password = pw
		a.audit(r, store.ActionUserPasswordReset, aboutUser(u), "Bulk action")
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
		a.runBulk(w, r, body.UserIDs, action, false, func(u *store.User, _ *bulkResult) (string, error) {
			if add {
				if in[u.ID] {
					return "Already in " + g.Name + ".", nil
				}
				if err := a.store.AddGroupMember(r.Context(), g.ID, u.ID); err != nil {
					return "", err
				}
				a.audit(r, store.ActionGroupMemberAdded, aboutUser(u), "Group: "+g.Name)
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
