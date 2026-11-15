package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/thekestongroup/id/internal/store"
)

// Product licences (store/licences.go): which of Keston's products each
// user may use. No seat limits yet.

// GET …/products: Keston's products, and how many users have each.
func (a *API) listProducts(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.Products(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// PUT …/users/{id}/licences {products}: exactly these products.
func (a *API) putLicences(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body struct {
		Products []string `json:"products"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !a.setLicences(w, r, u, body.Products) {
		return
	}
	list, err := a.store.Licences(r.Context(), u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"licences": list})
}

// setLicences sets them and records it, or writes the error.
func (a *API) setLicences(w http.ResponseWriter, r *http.Request, u *store.User, products []string) bool {
	err := a.applyLicences(r, u, products)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "products", "Choose from Keston’s products")
		return false
	}
	if err != nil {
		serverError(w, r, err)
		return false
	}
	return true
}

// applyLicences sets someone's licences and records the change.
func (a *API) applyLicences(r *http.Request, u *store.User, products []string) error {
	if products == nil {
		products = []string{}
	}
	me := caller(r).ID
	added, removed, err := a.store.SetLicences(r.Context(), u.ID, &me, products)
	if err != nil {
		return err
	}
	if len(added)+len(removed) > 0 {
		slog.Info("licences changed", "user", u.ID, "added", added, "removed", removed, "by", me)
		a.audit(r, store.ActionUserLicences, aboutUser(u), a.licenceSummary(r.Context(), added, removed))
	}
	return nil
}

// checkProducts: whether these are all Keston products (writing the error
// if not, or if the caller can't assign licences).
func (a *API) checkProducts(w http.ResponseWriter, r *http.Request, products []string) bool {
	if len(products) == 0 {
		return true
	}
	if !can(r, store.PermLicences) {
		writeFieldError(w, "licences", "You can't assign licences.")
		return false
	}
	known, err := a.store.ProductIDs(r.Context())
	if err != nil {
		serverError(w, r, err)
		return false
	}
	for _, p := range products {
		if !slices.Contains(known, p) {
			writeFieldError(w, "licences", "Choose from Keston’s products")
			return false
		}
	}
	return true
}

// licenceSummary: "Added: Keston Work. Removed: Keston Learn".
func (a *API) licenceSummary(ctx context.Context, added, removed []string) string {
	names := map[string]string{}
	if list, err := a.store.BuiltinClients(ctx); err == nil {
		for _, c := range list {
			names[c.ID] = c.Name
		}
	}
	label := func(ids []string) string {
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = names[id]
			if out[i] == "" {
				out[i] = id
			}
		}
		return strings.Join(out, ", ")
	}
	parts := []string{}
	if len(added) > 0 {
		parts = append(parts, "Added: "+label(added))
	}
	if len(removed) > 0 {
		parts = append(parts, "Removed: "+label(removed))
	}
	return strings.Join(parts, ". ")
}

// GET …/users/{id}/apps: the apps this user has (or is kept from), as the
// licences and app access settings work out for them: forced (always on),
// enabled (on, and they can remove it), disabled (turned off by app
// access), or no_licence (a Keston product they have no licence for). Apps
// with no setting that they haven't signed in to aren't listed.
func (a *API) userApps(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	ctx := r.Context()
	eff, err := a.store.EffectiveApps(ctx, u)
	if err != nil {
		serverError(w, r, err)
		return
	}
	all, err := a.store.ClientsFor(ctx, u.OrganisationID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	type row struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Publisher string `json:"publisher"`
		Access    string `json:"access"`
	}
	out := []row{}
	for _, c := range all {
		mode, ok := eff[c.ID]
		if !ok || c.ID == ClientID {
			continue
		}
		if mode == store.AppDisabled && c.Builtin {
			if licensed, err := a.store.Licensed(ctx, u, c.ID); err == nil && !licensed {
				mode = "no_licence"
			}
		}
		out = append(out, row{c.ID, c.Name, c.Publisher, mode})
	}
	writeJSON(w, http.StatusOK, out)
}
