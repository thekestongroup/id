package adminapi

// Apps (Keston Admin → Apps): every app the organisation has (Keston's, and
// its own), each with the organisation's default access, and per app ordered
// access rules like the MFA custom rules (store/app_rules.go). Users with
// "Set app access".
//
//	GET    …/apps                          every app, with its default and number of rules
//	GET    …/apps/{clientID}               one app
//	PUT    …/apps/{clientID} {mode}        the default: forced, enabled, disabled ("" removes it)
//	GET    …/apps/{clientID}/rules         its rules, in order
//	POST   …/apps/{clientID}/rules         a new rule (last)
//	PUT    …/apps/{clientID}/rules/{id}    change one
//	DELETE …/apps/{clientID}/rules/{id}
//	PUT    …/apps/{clientID}/rules/order {ids}
//	GET    …/apps/{clientID}/rules/options the users and groups a rule can be about

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

func (a *API) appRoutes(r chi.Router) {
	r.Get("/", a.listApps)
	r.Get("/{clientID}", a.getApp)
	r.Put("/{clientID}", a.putAppPolicy)
	r.Get("/{clientID}/rules", a.listAppRules)
	r.Post("/{clientID}/rules", a.saveAppRule)
	r.Put("/{clientID}/rules/order", a.orderAppRules)
	r.Get("/{clientID}/rules/options", a.appRuleOptions)
	r.Put("/{clientID}/rules/{ruleID}", a.saveAppRule)
	r.Delete("/{clientID}/rules/{ruleID}", a.deleteAppRule)
}

type appJSON struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Publisher    string `json:"publisher"`
	Description  string `json:"description"`
	Verification string `json:"verification"`
	// One of Keston's own apps: forced unless the organisation says otherwise.
	Builtin bool `json:"builtin"`
	// Added by this organisation (Own apps): "oidc" or "saml".
	Own      bool   `json:"own"`
	Protocol string `json:"protocol"`
	LogoURL  string `json:"logoUrl"`
	// "keston" (The Keston Group), "organisation" (this one's own) or "other".
	PublisherKind string `json:"publisherKind"`
	// "web" (has a secret), "native" (single-page or mobile) or "saml".
	Type string `json:"type"`
	// The organisation's default: forced, enabled or disabled; "" when not
	// set (Keston's own apps are then forced, others up to each person).
	DefaultMode string `json:"defaultMode"`
	// What it is without a setting: forced for Keston's own apps, else "".
	Fallback  string `json:"fallback"`
	RuleCount int    `json:"ruleCount"`
	// A Keston-wide app: who manages it, "deployment" or "admin" (and for
	// those, whether a TKG Admin has retired it).
	KestonWide bool   `json:"kestonWide"`
	ManagedBy  string `json:"managedBy"`
	Retired    bool   `json:"retired"`
	// The caller (a TKG Admin in The Keston Group) can change it in Keston Admin.
	CanManage bool `json:"canManage"`
}

func (a *API) appView(r *http.Request, c *store.Client, defaults map[string]string, counts map[string]int) appJSON {
	org := organisation(r)
	v := appJSON{ID: c.ID, Name: c.Name, Publisher: c.Publisher, Description: c.Description,
		Verification: c.Verification, Builtin: c.Builtin, Own: c.OrganisationID != nil, Protocol: c.Protocol,
		LogoURL: c.LogoURL, DefaultMode: defaults[c.ID], RuleCount: counts[c.ID], KestonWide: c.OrganisationID == nil,
		ManagedBy: c.ManagedBy, Retired: c.RetiredAt != nil}
	switch {
	case c.OrganisationID != nil:
		v.PublisherKind = "organisation"
		v.Publisher = org.Name
	case c.Publisher == store.KestonPublisher:
		v.PublisherKind = "keston"
	default:
		v.PublisherKind = "other"
	}
	switch {
	case c.Protocol == "saml":
		v.Type = "saml"
	case c.Native:
		v.Type = typeNative
	default:
		v.Type = typeWeb
	}
	if c.Builtin {
		v.Fallback = store.AppForced
	}
	v.CanManage = v.KestonWide && c.ManagedBy == store.ManagedByAdmin && a.canManageKestonApps(r)
	return v
}

func (a *API) appViews(r *http.Request) ([]appJSON, error) {
	ctx := r.Context()
	org := organisation(r)
	all, err := a.store.ClientsFor(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	policies, err := a.store.AppPolicies(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	counts, err := a.store.AppRuleCounts(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	defaults := map[string]string{}
	for _, p := range policies {
		defaults[p.ClientID] = p.Mode
	}
	apps := []appJSON{}
	for i := range all {
		if all[i].ID == ClientID { // Keston Admin is for admins, not set per app
			continue
		}
		apps = append(apps, a.appView(r, &all[i], defaults, counts))
	}
	// TKG Admins in The Keston Group also see the Keston-wide apps they've retired.
	if a.canManageKestonApps(r) {
		list, err := a.store.KestonClients(ctx)
		if err != nil {
			return nil, err
		}
		for i := range list {
			if list[i].RetiredAt != nil {
				apps = append(apps, a.appView(r, &list[i], defaults, counts))
			}
		}
	}
	return apps, nil
}

// GET …/apps: every app, with the organisation's default for it. (groups and
// policies are what the first version of this page used; the page now reads
// each app's defaultMode.)
func (a *API) listApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := organisation(r)
	apps, err := a.appViews(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	groups, err := a.store.Groups(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	def := map[string]string{}
	for _, v := range apps {
		if v.DefaultMode != "" {
			def[v.ID] = v.DefaultMode
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"apps":            apps,
		"groups":          groups,
		"policies":        map[string]any{"default": def, "groups": map[string]any{}},
		"canManageKeston": a.canManageKestonApps(r),
	})
}

// appFor: the app in the URL if the organisation has it (not Keston Admin).
func (a *API) appFor(w http.ResponseWriter, r *http.Request) *store.Client {
	org := organisation(r)
	c, err := a.store.ClientByID(r.Context(), chi.URLParam(r, "clientID"))
	if err != nil || c.ID == ClientID || (c.OrganisationID != nil && *c.OrganisationID != org.ID) ||
		(c.RetiredAt != nil && !a.canManageKestonApps(r)) {
		writeError(w, http.StatusNotFound, "not_found", "That app doesn't exist.")
		return nil
	}
	return c
}

// GET …/apps/{clientID}
func (a *API) getApp(w http.ResponseWriter, r *http.Request) {
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	org := organisation(r)
	policies, err := a.store.AppPolicies(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	counts, err := a.store.AppRuleCounts(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	defaults := map[string]string{}
	for _, p := range policies {
		defaults[p.ClientID] = p.Mode
	}
	writeJSON(w, http.StatusOK, a.appView(r, c, defaults, counts))
}

// PUT …/apps/{clientID} {mode}: the organisation's default access to an app.
// mode "" removes the setting.
func (a *API) putAppPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode    string  `json:"mode"`
		GroupID *string `json:"groupId"`
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
	if body.GroupID != nil && *body.GroupID != "" {
		writeFieldError(w, "groupId", "Settings for a group are rules now: add one on the app's Access tab")
		return
	}
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	ctx := r.Context()
	org := organisation(r)
	before := ""
	if policies, err := a.store.AppPolicies(ctx, org.ID); err == nil {
		for _, p := range policies {
			if p.ClientID == c.ID {
				before = p.Mode
			}
		}
	}
	if err := a.store.SetAppPolicy(ctx, org.ID, c.ID, body.Mode); err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionAppAccess, aboutApp(c), change("Default state", modeLabel(before), modeLabel(body.Mode)))
	w.WriteHeader(http.StatusNoContent)
}

// ── Rules ────────────────────────────────────────────────────────────────

// GET …/apps/{clientID}/rules: in order.
func (a *API) listAppRules(w http.ResponseWriter, r *http.Request) {
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	rules, err := a.store.AppRules(r.Context(), organisation(r).ID, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// POST …/apps/{clientID}/rules, PUT …/apps/{clientID}/rules/{id}
// {name, enabled, mode, users, groups, ipRanges}: a new rule (last) or a
// change to one. Users and groups must be the organisation's.
func (a *API) saveAppRule(w http.ResponseWriter, r *http.Request) {
	var in struct {
		store.AppRule
		Enabled *bool `json:"enabled"` // turned on unless it says otherwise
	}
	if !decode(w, r, &in) {
		return
	}
	body := in.AppRule
	body.Enabled = in.Enabled == nil || *in.Enabled
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	body.ID = chi.URLParam(r, "ruleID")
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 100 {
		writeFieldError(w, "name", "Give the rule a name")
		return
	}
	switch body.Mode {
	case store.AppForced, store.AppEnabled, store.AppDisabled:
	default:
		writeFieldError(w, "mode", "Choose forced, enabled or disabled")
		return
	}
	for _, list := range []*[]string{&body.Users, &body.Groups, &body.IPRanges} {
		if *list == nil {
			*list = []string{}
		}
	}
	if !a.checkRuleConditions(w, r, body.Users, body.Groups, body.IPRanges) {
		return
	}
	org := organisation(r)
	isNew := body.ID == ""
	saved, err := a.store.SaveAppRule(r.Context(), org.ID, c.ID, body)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That rule doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	verb := "Rule changed: "
	if isNew {
		verb = "Rule added: "
	}
	slog.Info("app rule saved", "organisation", org.ID, "app", c.ID, "rule", saved.ID, "by", caller(r).ID)
	a.audit(r, store.ActionAppAccess, aboutApp(c), verb+saved.Name+" ("+modeLabel(saved.Mode)+")")
	status := http.StatusOK
	if isNew {
		status = http.StatusCreated
	}
	writeJSON(w, status, saved)
}

// DELETE …/apps/{clientID}/rules/{id}
func (a *API) deleteAppRule(w http.ResponseWriter, r *http.Request) {
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	id := chi.URLParam(r, "ruleID")
	org := organisation(r)
	rules, _ := a.store.AppRules(r.Context(), org.ID, c.ID)
	err := a.store.DeleteAppRule(r.Context(), org.ID, c.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That rule doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	for _, rule := range rules {
		if rule.ID == id {
			a.audit(r, store.ActionAppAccess, aboutApp(c), "Rule deleted: "+rule.Name)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// PUT …/apps/{clientID}/rules/order {ids}: every rule of the app, in the
// order they're tried.
func (a *API) orderAppRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !decode(w, r, &body) {
		return
	}
	c := a.appFor(w, r)
	if c == nil {
		return
	}
	org := organisation(r)
	rules, err := a.store.AppRules(r.Context(), org.ID, c.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	valid := len(body.IDs) == len(rules)
	for _, rule := range rules {
		valid = valid && slices.Contains(body.IDs, rule.ID)
	}
	if !valid {
		writeError(w, http.StatusBadRequest, "bad_request", "Include every rule, once.")
		return
	}
	if err := a.store.OrderAppRules(r.Context(), org.ID, c.ID, body.IDs); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "bad_request", "Include every rule, once.")
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionAppAccess, aboutApp(c), "Rules reordered")
	a.listAppRules(w, r)
}

// GET …/apps/{clientID}/rules/options: the users and groups a rule can be
// about, for whoever sets app access (who may not have the permissions to
// list them elsewhere).
func (a *API) appRuleOptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := organisation(r)
	users, err := a.store.UsersInOrganisation(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	groups, err := a.store.Groups(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	type named struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Extra string `json:"extra,omitempty"`
	}
	out := struct {
		Users  []named `json:"users"`
		Groups []named `json:"groups"`
	}{[]named{}, []named{}}
	for _, u := range users {
		if !u.IsSupport() {
			out.Users = append(out.Users, named{u.ID, u.Name, u.Email})
		}
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, named{ID: g.ID, Name: g.Name})
	}
	writeJSON(w, http.StatusOK, out)
}
