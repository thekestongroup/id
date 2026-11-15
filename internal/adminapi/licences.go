package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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
	if products == nil {
		products = []string{}
	}
	me := caller(r).ID
	added, removed, err := a.store.SetLicences(r.Context(), u.ID, &me, products)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "products", "Choose from Keston’s products")
		return false
	}
	if err != nil {
		serverError(w, r, err)
		return false
	}
	if len(added)+len(removed) > 0 {
		slog.Info("licences changed", "user", u.ID, "added", added, "removed", removed, "by", me)
		a.audit(r, store.ActionUserLicences, aboutUser(u), a.licenceSummary(r.Context(), added, removed))
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
