package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thekestongroup/id/internal/store"
)

// Admin roles (store/roles.go): built-in sets of permissions given straight
// to a user. Giving or taking a role needs "Give permissions" and every
// permission the role gives (global admins can give any).

// GET …/roles: the roles there are.
func (a *API) listRoles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, store.AdminRoles)
}

// checkRoles: whether the caller may give (or take) these roles, writing
// the error if not.
func checkRoles(w http.ResponseWriter, r *http.Request, roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	for _, id := range roles {
		if store.RoleByID(id) == nil {
			writeFieldError(w, "roles", "Choose from the admin roles")
			return false
		}
	}
	if caller(r).Role == "global_admin" {
		return true
	}
	if !can(r, store.PermAssign) || !permsIn(r, organisation(r).ID).Covers(store.RolePermissions(roles)) {
		writeFieldError(w, "roles", "You can only give roles whose permissions you have yourself.")
		return false
	}
	return true
}

// PUT …/users/{id}/roles {roles}: exactly these admin roles.
func (a *API) putRoles(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body struct {
		Roles []string `json:"roles"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Roles == nil {
		body.Roles = []string{}
	}
	before, err := a.store.RolesOf(r.Context(), u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// Taking a role away needs the same as giving it.
	if !checkRoles(w, r, append(append([]string{}, body.Roles...), before...)) {
		return
	}
	if !a.applyRoles(w, r, u, body.Roles) {
		return
	}
	list, err := a.store.RolesOf(r.Context(), u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": list})
}

// applyRoles sets them and records the change, or writes the error.
func (a *API) applyRoles(w http.ResponseWriter, r *http.Request, u *store.User, roles []string) bool {
	added, removed, err := a.store.SetRoles(r.Context(), u.ID, roles)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "roles", "Choose from the admin roles")
		return false
	}
	if err != nil {
		serverError(w, r, err)
		return false
	}
	if len(added)+len(removed) > 0 {
		slog.Info("roles changed", "user", u.ID, "added", added, "removed", removed, "by", caller(r).ID)
		parts := []string{}
		if len(added) > 0 {
			parts = append(parts, "Added: "+roleLabels(added))
		}
		if len(removed) > 0 {
			parts = append(parts, "Removed: "+roleLabels(removed))
		}
		a.audit(r, store.ActionUserRoles, aboutUser(u), strings.Join(parts, ". "))
		if len(added) > 0 {
			a.alert(r, store.NewAlert{Kind: store.AlertAdminRole, SubjectID: u.ID, SubjectName: u.Name,
				Title:     "Admin role given to " + u.Name,
				Body:      actorName(r) + " gave " + u.Name + " the admin role " + roleLabels(added) + ".",
				Params:    map[string]any{"by": actorName(r), "roles": roleLabels(added)},
				DedupeKey: store.AlertAdminRole + ":" + u.ID + ":" + strings.Join(added, ","), DedupeFor: 10 * time.Minute})
		}
	}
	return true
}

func roleLabels(ids []string) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		if role := store.RoleByID(id); role != nil {
			out[i] = role.Label
		} else {
			out[i] = id
		}
	}
	return strings.Join(out, ", ")
}
