package api

import (
	"github.com/thekestongroup/id/internal/clientip"
	"net/http"

	"github.com/thekestongroup/id/internal/store"
)

// logSignIn records a sign-in attempt (Keston Admin → Logs → Sign-ins),
// with where it came from.
func (a *API) logSignIn(r *http.Request, e store.SignIn) {
	e.IP, e.UserAgent = clientip.From(r), r.UserAgent()
	a.store.LogSignIn(r.Context(), e)
}

// failReason: why a correct password still doesn't sign someone in.
func failReason(u *store.User) string {
	if u.Status != "active" {
		return store.ReasonDisabled
	}
	if !u.OrganisationVerified {
		return store.ReasonUnverifiedOrg
	}
	return store.ReasonExpired
}

// writeUnverified: the answer to a sign-in by someone whose organisation is
// still waiting to be verified by The Keston Group.
func writeUnverified(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "organisation_unverified",
		"Your organisation is waiting to be verified. When it's verified, you'll be able to sign in.")
}
