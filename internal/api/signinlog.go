package api

import (
	"net/http"

	"github.com/thekestongroup/id/internal/store"
)

// logSignIn records a sign-in attempt (Keston Admin → Logs → Sign-ins),
// with where it came from.
func (a *API) logSignIn(r *http.Request, e store.SignIn) {
	e.IP, e.UserAgent = clientIP(r), r.UserAgent()
	a.store.LogSignIn(r.Context(), e)
}

// failReason: why a correct password still doesn't sign someone in.
func failReason(u *store.User) string {
	if u.Status != "active" {
		return store.ReasonDisabled
	}
	return store.ReasonExpired
}
