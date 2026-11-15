package api

import (
	"net/http"

	"github.com/thekestongroup/id/internal/store"
)

// ActiveSessionID: the browser's active, fully signed-in Keston ID session
// ("" if none). SAML sign-in uses it to send the response only to the
// browser that signed in. Required actions (a new password, MFA set up)
// must be done first, as for OIDC.
func (a *API) ActiveSessionID(r *http.Request) string {
	cur := a.current(r)
	if cur == nil {
		return ""
	}
	if _, err := a.settle(r.Context(), cur); err != nil || cur.session.Stage != store.StageVerified {
		return ""
	}
	return cur.session.ID
}
