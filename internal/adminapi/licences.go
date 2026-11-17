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
// user may use, within the licences the organisation has for each (seats, or
// unlimited; set by TKG Admins).

// GET …/products: Keston's products, how many users have each, and the
// organisation's licences for it (seats, unlimited, available, overAllocated).
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
	list, err := a.store.DirectLicences(r.Context(), u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"licences": list})
}

// setLicences sets them and records it, or writes the error.
func (a *API) setLicences(w http.ResponseWriter, r *http.Request, u *store.User, products []string) bool {
	err := a.applyLicences(r, u, products)
	if writeNoSeats(w, err) {
		return false
	}
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

// noSeatsMessage: why a licence can't be assigned.
func noSeatsMessage(e *store.NoSeatsError) string {
	names := strings.Join(e.Names, ", ")
	if e.Over {
		return "This organisation is over its allocation of " + names + " licences. Remove some licences or ask The Keston Group for more."
	}
	return "There are no " + names + " licences left. Remove some licences or ask The Keston Group for more."
}

// writeNoSeats writes the error and returns true if err is a *NoSeatsError.
func writeNoSeats(w http.ResponseWriter, err error) bool {
	var e *store.NoSeatsError
	if !errors.As(err, &e) {
		return false
	}
	writeError(w, http.StatusConflict, "no_licences_left", noSeatsMessage(e))
	return true
}

// checkSeats: whether the organisation has licences for one more user to
// have these products (writing the error if not).
func (a *API) checkSeats(w http.ResponseWriter, r *http.Request, products []string) bool {
	if len(products) == 0 {
		return true
	}
	err := a.store.CheckSeats(r.Context(), organisation(r).ID, products, 1)
	if err == nil {
		return true
	}
	if !writeNoSeats(w, err) {
		serverError(w, r, err)
	}
	return false
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

// POST …/users/bulk/licences {userIds, add, remove}: gives and takes away
// licences. Each user is done or skipped with the reason, in order, so when
// the seats run out the first users are done and the rest skipped ("No
// Keston Work licences left"). Taking licences away always works.
func (a *API) bulkLicences(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserIDs []string `json:"userIds"`
		Add     []string `json:"add"`
		Remove  []string `json:"remove"`
	}
	if !decode(w, r, &body) || !checkIDs(w, body.UserIDs) {
		return
	}
	if len(body.Add)+len(body.Remove) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "Choose licences to add or remove.")
		return
	}
	if !a.checkProducts(w, r, append(slices.Clone(body.Add), body.Remove...)) {
		return
	}
	a.runBulk(w, r, body.UserIDs, "licences", false, func(u *store.User, res *bulkResult) (string, error) {
		// Only what's assigned to them: group licences aren't turned into
		// assigned ones.
		have, err := a.store.DirectLicences(r.Context(), u.ID)
		if err != nil {
			return "", err
		}
		want := slices.Clone(have)
		for _, p := range body.Add {
			if !slices.Contains(want, p) {
				want = append(want, p)
			}
		}
		want = slices.DeleteFunc(want, func(p string) bool { return slices.Contains(body.Remove, p) })
		err = a.applyLicences(r, u, want)
		var e *store.NoSeatsError
		if errors.As(err, &e) {
			return "No " + strings.Join(e.Names, ", ") + " licences left.", nil
		}
		return "", err
	})
}

// PUT …/licences {allocations: [{product, seats}]}: how many licences the
// organisation has for each product (seats null is unlimited). TKG Admins
// only. Seats below the licences in use are allowed (the organisation is
// over its allocation until it's under); returns the products as GET …/products.
func (a *API) putAllocations(w http.ResponseWriter, r *http.Request) {
	if !caller(r).PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only TKG Admins can change an organisation's licences.")
		return
	}
	var body struct {
		Allocations []struct {
			Product string `json:"product"`
			Seats   *int   `json:"seats"`
		} `json:"allocations"`
	}
	if !decode(w, r, &body) {
		return
	}
	seats := map[string]*int{}
	for _, al := range body.Allocations {
		if al.Seats != nil && (*al.Seats < 0 || *al.Seats > 1_000_000) {
			writeFieldError(w, "seats", "Enter a number of seats from 0 to 1,000,000, or choose unlimited.")
			return
		}
		seats[al.Product] = al.Seats
	}
	me := caller(r).ID
	org := organisation(r)
	summary, err := a.store.SetAllocations(r.Context(), org.ID, &me, seats)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "product", "Choose from Keston’s products")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	if summary != "" {
		slog.Info("licence allocations changed", "organisation", org.ID, "by", me)
		a.audit(r, store.ActionOrgLicences, aboutOrg(org), summary)
	}
	a.listProducts(w, r)
}
