package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/thekestongroup/id/internal/store"
)

// ── Group licences ───────────────────────────────────────────────────────
//
// A group can give its members licences for Keston's products (store/
// group_licences.go; the seat rule is in migration 0074): members have them
// as if assigned, shown on their page as "From group …". Seats are never a
// reason to refuse: members past the last seat are listed as not licensed.

// GET …/groups/{id}/licences: {products: [IDs the group gives], issues:
// [{userId, name, email, products}]}: the members with no seat left for a
// product the group gives them (in the order they'd get one).
func (a *API) getGroupLicences(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	products, err := a.store.GroupLicences(r.Context(), g.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	issues, err := a.store.GroupLicenceIssues(r.Context(), organisation(r).ID, g.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"products": products, "issues": issues})
}

// PUT …/groups/{id}/licences {products}: exactly these products, for every
// member. Needs Assign licences. Taking one away removes it from members who
// have it only through this group, not from those it's assigned to.
func (a *API) putGroupLicences(w http.ResponseWriter, r *http.Request) {
	g := a.group(w, r)
	if g == nil {
		return
	}
	var body struct {
		Products []string `json:"products"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Products == nil {
		body.Products = []string{}
	}
	me := caller(r).ID
	added, removed, err := a.store.SetGroupLicences(r.Context(), organisation(r).ID, g.ID, &me, body.Products)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "products", "Choose from Keston’s products")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	if len(added)+len(removed) > 0 {
		slog.Info("group licences changed", "group", g.ID, "added", added, "removed", removed, "by", me)
		a.audit(r, store.ActionGroupLicences, aboutGroup(g), a.licenceSummary(r.Context(), added, removed))
	}
	a.getGroupLicences(w, r)
}

// notLicensedNote: for a bulk result, when someone was added to a group but
// has no seat for what it gives them ("" if they do).
func (a *API) notLicensedNote(r *http.Request, u *store.User) string {
	names, err := a.store.UnlicensedProducts(r.Context(), u.ID)
	if err != nil || len(names) == 0 {
		return ""
	}
	return "Added, but not licensed: no " + strings.Join(names, ", ") + " licences left."
}
