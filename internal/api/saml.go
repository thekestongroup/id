package api

import "net/http"

// ActiveSessionID: the browser's active, fully signed-in Keston ID session
// ("" if none). SAML sign-in uses it to send the response only to the
// browser that signed in.
func (a *API) ActiveSessionID(r *http.Request) string {
	cur := a.current(r)
	if cur == nil || cur.session.Stage != "verified" {
		return ""
	}
	return cur.session.ID
}
