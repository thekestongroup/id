package adminapi

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// ── Groups ───────────────────────────────────────────────────────────────

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.store.Groups(r.Context(), organisation(r).ID)
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
	out := make([]userJSON, len(members))
	for i := range members {
		out[i] = a.userView(&members[i])
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
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	if err := a.store.DeleteGroup(r.Context(), organisation(r).ID, g.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addMember(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	u, err := a.store.UserByID(r.Context(), chi.URLParam(r, "userID"))
	if err != nil || u.OrganisationID != organisation(r).ID || u.IsSupport() {
		writeError(w, http.StatusNotFound, "not_found", "That user doesn't exist.")
		return
	}
	if err := a.store.AddGroupMember(r.Context(), g.ID, u.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) removeMember(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	if err := a.store.RemoveGroupMember(r.Context(), g.ID, chi.URLParam(r, "userID")); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── App access ───────────────────────────────────────────────────────────

type appJSON struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Publisher    string `json:"publisher"`
	Verification string `json:"verification"`
	// One of Keston's own apps: forced unless the organisation says otherwise.
	Builtin bool `json:"builtin"`
}

// GET …/apps: every app, the groups, and the organisation's settings:
// policies.default[appId] and policies.groups[groupId][appId].
func (a *API) listApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := organisation(r)
	all, err := a.store.AllClients(ctx)
	if err != nil {
		serverError(w, r, err)
		return
	}
	groups, err := a.store.Groups(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	policies, err := a.store.AppPolicies(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	apps := []appJSON{}
	for _, c := range all {
		if c.ID == ClientID { // Keston Admin is for admins, not set per app
			continue
		}
		apps = append(apps, appJSON{ID: c.ID, Name: c.Name, Publisher: c.Publisher, Verification: c.Verification,
			Builtin: c.Builtin})
	}
	def := map[string]string{}
	byGroup := map[string]map[string]string{}
	for _, p := range policies {
		if p.GroupID == nil {
			def[p.ClientID] = p.Mode
			continue
		}
		if byGroup[*p.GroupID] == nil {
			byGroup[*p.GroupID] = map[string]string{}
		}
		byGroup[*p.GroupID][p.ClientID] = p.Mode
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apps":     apps,
		"groups":   groups,
		"policies": map[string]any{"default": def, "groups": byGroup},
	})
}

// PUT …/apps/{clientID} {groupId?, mode}: set the default (no groupId) or a
// group's access to an app. mode "" removes the setting.
func (a *API) putAppPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GroupID *string `json:"groupId"`
		Mode    string  `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch body.Mode {
	case "", store.AppForced, store.AppEnabled, store.AppDisabled:
	default:
		writeFieldError(w, "mode", "Choose forced, enabled or disabled")
		return
	}
	ctx := r.Context()
	org := organisation(r)
	c, err := a.store.ClientByID(ctx, chi.URLParam(r, "clientID"))
	if err != nil || c.ID == ClientID {
		writeError(w, http.StatusNotFound, "not_found", "That app doesn't exist.")
		return
	}
	if body.GroupID != nil && *body.GroupID == "" {
		body.GroupID = nil
	}
	if body.GroupID != nil {
		if _, err := a.store.Group(ctx, org.ID, *body.GroupID); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "That group doesn't exist.")
			return
		}
	}
	if err := a.store.SetAppPolicy(ctx, org.ID, body.GroupID, c.ID, body.Mode); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
