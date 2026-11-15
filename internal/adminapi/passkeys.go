package adminapi

import (
	"log/slog"
	"net/http"
)

// Passkeys and security keys: Keston Admin shows how many a user has, and
// admins who can turn off MFA can remove them (when one's lost or stolen).
// People add, name and remove their own in their Keston account.

// withPasskeys adds a user's passkey count to their view: with any, MFA is on.
func withPasskeys(v userJSON, n int) userJSON {
	v.Passkeys = n
	v.MFA = v.MFA || n > 0
	return v
}

func (a *API) withPasskeyCount(r *http.Request, v userJSON) userJSON {
	n, err := a.store.PasskeyCount(r.Context(), v.ID)
	if err != nil {
		slog.WarnContext(r.Context(), "counting passkeys", "user", v.ID, "error", err)
	}
	return withPasskeys(v, n)
}

// DELETE …/users/{id}/passkeys: removes every passkey and security key from
// the user's account. An authenticator app, if they have one, stays on.
func (a *API) removePasskeys(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	removed, err := a.store.DeletePasskeys(r.Context(), u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if removed == 0 {
		writeError(w, http.StatusConflict, "none", u.Name+" doesn't have any passkeys.")
		return
	}
	slog.Info("passkeys removed by an admin", "user", u.ID, "organisation", organisation(r).ID, "by", caller(r).ID,
		"passkeys_removed", removed)
	updated, _ := a.store.UserByID(r.Context(), u.ID)
	writeJSON(w, http.StatusOK, a.withPasskeyCount(r, a.userView(updated)))
}
