package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/thekestongroup/id/internal/store"
)

// Several Keston accounts can be signed in to one browser (switching
// between them, like Google's account chooser). The session cookie holds
// their tokens, the active one first. Each is a separate Keston ID session.
const (
	sessionCookie = "kid_session"
	tokenSep      = "~"
	maxAccounts   = 5
)

func tokens(r *http.Request) []string {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	return strings.Split(c.Value, tokenSep)
}

func (a *API) writeTokens(w http.ResponseWriter, list []string) {
	if len(list) == 0 {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
			Secure: a.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: -1})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: strings.Join(list, tokenSep), Path: "/", HttpOnly: true,
		Secure: a.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: int(a.cfg.SessionTTL.Seconds()),
	})
}

// signedIn is every account still signed in to this browser, active first.
func (a *API) signedIn(r *http.Request) []*current {
	var out []*current
	for _, token := range tokens(r) {
		sess, err := a.store.SessionByToken(r.Context(), token)
		if err != nil {
			continue
		}
		user, err := a.store.UserByID(r.Context(), sess.UserID)
		if err != nil || user.Status != "active" {
			continue
		}
		out = append(out, &current{session: sess, user: user, token: token})
	}
	return out
}

// current is the active account, if any.
func (a *API) current(r *http.Request) *current {
	if all := a.signedIn(r); len(all) > 0 {
		return all[0]
	}
	return nil
}

// addSession makes a new session the active one. Signing in again as an
// account that's already here replaces its old session.
func (a *API) addSession(w http.ResponseWriter, r *http.Request, token, userID string) {
	list := []string{token}
	for _, c := range a.signedIn(r) {
		if c.user.ID == userID {
			a.end(r.Context(), c.session.ID)
			continue
		}
		if len(list) < maxAccounts {
			list = append(list, c.token)
		}
	}
	a.writeTokens(w, list)
}

// end signs one session out of Keston ID and every app it signed in to.
func (a *API) end(ctx context.Context, sessionID string) {
	if err := a.endSession(ctx, sessionID); err != nil {
		slog.Warn("signing out of apps", "error", err)
	}
	_ = a.store.DeleteSession(ctx, sessionID)
}

// EndBrowserSession signs the active account out (Keston ID and its apps),
// for the OIDC end_session endpoint. Other accounts stay signed in.
func (a *API) EndBrowserSession(w http.ResponseWriter, r *http.Request) {
	all := a.signedIn(r)
	if len(all) == 0 {
		a.writeTokens(w, nil)
		return
	}
	a.end(r.Context(), all[0].session.ID)
	rest := []string{}
	for _, c := range all[1:] {
		rest = append(rest, c.token)
	}
	a.writeTokens(w, rest)
}

type accountView struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Organisation string `json:"organisation"`
	Active       bool   `json:"active"`
	// Signed in with a password, but not the second step yet.
	NeedsTwoStep bool `json:"needsTwoStep"`
}

// GET /api/accounts: the accounts signed in to this browser.
func (a *API) accounts(w http.ResponseWriter, r *http.Request) {
	out := []accountView{}
	for i, c := range a.signedIn(r) {
		out = append(out, accountView{ID: c.session.ID, Name: c.user.Name, Email: c.user.Email,
			Organisation: c.user.Organisation, Active: i == 0, NeedsTwoStep: c.session.Stage != "verified"})
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/accounts/switch {id, authRequestID}: use another signed-in
// account (and, during an app's sign-in, carry on with it).
func (a *API) switchAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID            string `json:"id"`
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	all := a.signedIn(r)
	var chosen *current
	list := []string{}
	for _, c := range all {
		if c.session.ID == body.ID {
			chosen = c
		} else {
			list = append(list, c.token)
		}
	}
	if chosen == nil {
		writeError(w, http.StatusNotFound, "not_found", "That account isn't signed in any more.")
		return
	}
	a.writeTokens(w, append([]string{chosen.token}, list...))
	if body.AuthRequestID != "" {
		_ = a.store.ChooseAccount(r.Context(), body.AuthRequestID)
	}
	a.respondNext(w, r, chosen, body.AuthRequestID)
}

// POST /api/sign-out {all}: sign the active account out (or every account),
// from Keston ID and from every app it signed in to.
func (a *API) signOut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		All bool `json:"all"`
	}
	_ = decodeOptional(r, &body)
	if !body.All {
		a.EndBrowserSession(w, r)
		// The active session is gone now, so this counts the others.
		writeJSON(w, http.StatusOK, map[string]int{"remaining": len(a.signedIn(r))})
		return
	}
	for _, c := range a.signedIn(r) {
		a.end(r.Context(), c.session.ID)
	}
	a.writeTokens(w, nil)
	writeJSON(w, http.StatusOK, map[string]int{"remaining": 0})
}

var _ = store.ErrNotFound
