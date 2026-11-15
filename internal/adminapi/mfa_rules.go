package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// MFA custom rules (store/mfa_rules.go): Security → Manage MFA. Each needs
// "Set the password policy and MFA".

// GET …/mfa-rules: in order.
func (a *API) listMFARules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.store.MFARules(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// POST …/mfa-rules, PUT …/mfa-rules/{id}
// {name, enabled, require, users, groups, apps, ipRanges}: a new rule (last)
// or a change to one. Users, groups and apps must be the organisation's; IP
// ranges are addresses (1.2.3.4) or ranges (10.0.0.0/8), v4 or v6.
func (a *API) saveMFARule(w http.ResponseWriter, r *http.Request) {
	var body store.MFARule
	if !decode(w, r, &body) {
		return
	}
	body.ID = chi.URLParam(r, "ruleID")
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 100 {
		writeFieldError(w, "name", "Give the rule a name")
		return
	}
	ctx := r.Context()
	org := organisation(r)
	for _, list := range []*[]string{&body.Users, &body.Groups, &body.Apps, &body.IPRanges} {
		if *list == nil {
			*list = []string{}
		}
	}
	if len(body.Users) > 0 {
		users, err := a.store.UsersInOrganisation(ctx, org.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		for _, id := range body.Users {
			if !slices.ContainsFunc(users, func(u store.User) bool { return u.ID == id }) {
				writeFieldError(w, "users", "Choose from your users")
				return
			}
		}
	}
	if len(body.Groups) > 0 {
		groups, err := a.store.Groups(ctx, org.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		for _, id := range body.Groups {
			if !slices.ContainsFunc(groups, func(g store.Group) bool { return g.ID == id }) {
				writeFieldError(w, "groups", "Choose from your groups")
				return
			}
		}
	}
	if len(body.Apps) > 0 {
		apps, err := a.store.ClientsFor(ctx, org.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		for _, id := range body.Apps {
			if !slices.ContainsFunc(apps, func(c store.Client) bool { return c.ID == id }) {
				writeFieldError(w, "apps", "Choose from your apps")
				return
			}
		}
	}
	for i, v := range body.IPRanges {
		p, ok := parseRange(v)
		if !ok {
			writeFieldError(w, "ipRanges", "“"+v+"” isn't an IP address or range, like 203.0.113.7 or 10.0.0.0/8")
			return
		}
		body.IPRanges[i] = p.String()
	}
	isNew := body.ID == ""
	saved, err := a.store.SaveMFARule(ctx, org.ID, body)
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
	slog.Info("mfa rule saved", "organisation", org.ID, "rule", saved.ID, "by", caller(r).ID)
	a.audit(r, store.ActionMFAPolicy, aboutOrg(org), verb+saved.Name)
	status := http.StatusOK
	if isNew {
		status = http.StatusCreated
	}
	writeJSON(w, status, saved)
}

// parseRange: an address (as a single-address range) or a CIDR range.
func parseRange(v string) (netip.Prefix, bool) {
	v = strings.TrimSpace(v)
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), true
	}
	if ip, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()), true
	}
	return netip.Prefix{}, false
}

// DELETE …/mfa-rules/{id}
func (a *API) deleteMFARule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "ruleID")
	org := organisation(r)
	rules, _ := a.store.MFARules(r.Context(), org.ID)
	err := a.store.DeleteMFARule(r.Context(), org.ID, id)
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
			a.audit(r, store.ActionMFAPolicy, aboutOrg(org), "Rule deleted: "+rule.Name)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// PUT …/mfa-rules/order {ids}: every rule, in the order they're tried.
func (a *API) orderMFARules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if !decode(w, r, &body) {
		return
	}
	org := organisation(r)
	rules, err := a.store.MFARules(r.Context(), org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if len(body.IDs) != len(rules) {
		writeError(w, http.StatusBadRequest, "bad_request", "Include every rule, once.")
		return
	}
	if err := a.store.OrderMFARules(r.Context(), org.ID, body.IDs); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "bad_request", "Include every rule, once.")
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	a.audit(r, store.ActionMFAPolicy, aboutOrg(org), "Rules reordered")
	a.listMFARules(w, r)
}

// GET …/mfa-rules/options: the users, groups and apps a rule can be about,
// for whoever sets the rules (who may not have the permissions to list them
// elsewhere).
func (a *API) mfaRuleOptions(w http.ResponseWriter, r *http.Request) {
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
	apps, err := a.store.ClientsFor(ctx, org.ID)
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
		Apps   []named `json:"apps"`
	}{[]named{}, []named{}, []named{}}
	for _, u := range users {
		if !u.IsSupport() {
			out.Users = append(out.Users, named{u.ID, u.Name, u.Email})
		}
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, named{ID: g.ID, Name: g.Name})
	}
	for _, c := range apps {
		if c.ID != ClientID { // Keston Admin itself
			out.Apps = append(out.Apps, named{c.ID, c.Name, c.Publisher})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
