package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// Moving an account to another organisation (store/moves.go): a global admin
// of its home organisation asks, a global admin of the receiving one
// accepts. Only global admins of the organisation itself (not Keston
// support accounts) can do either.

func (a *API) needGlobalAdmin(w http.ResponseWriter, r *http.Request) bool {
	if decides(caller(r), organisation(r).ID) {
		return true
	}
	writeError(w, http.StatusForbidden, "no_permission", "Only a global admin can move accounts between organisations.")
	return false
}

// GET …/moves: requests to move accounts out of or into this organisation.
func (a *API) listMoves(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.MovesOf(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// POST …/users/{userID}/move {domain}: ask to move this account to the
// organisation with that domain. The account keeps its username and gets
// the new domain once the other organisation's global admin accepts.
func (a *API) requestMove(w http.ResponseWriter, r *http.Request) {
	if !a.needGlobalAdmin(w, r) {
		return
	}
	u, err := a.store.UserByID(r.Context(), chi.URLParam(r, "userID"))
	if err != nil || u.OrganisationID != organisation(r).ID || u.Status == "deleted" {
		writeError(w, http.StatusNotFound, "not_found", "That user doesn't exist.")
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &body) {
		return
	}
	domain := normaliseDomain(body.Domain)
	to, err := a.store.OrganisationByDomain(r.Context(), domain)
	if err != nil || !to.Verified || to.ID == u.OrganisationID {
		writeFieldError(w, "domain", "There's no organisation we can move them to with that domain.")
		return
	}
	m, err := a.store.RequestMove(r.Context(), u, to, caller(r))
	switch {
	case errors.Is(err, store.ErrMoveNotAllowed):
		writeError(w, http.StatusConflict, "not_movable", "This kind of account can't be moved (Keston support accounts and TKG Admins).")
		return
	case errors.Is(err, store.ErrMoveLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", u.Name+" is your only global admin. Make someone else a global admin first.")
		return
	case errors.Is(err, store.ErrMoveEmailTaken):
		writeFieldError(w, "domain", "Someone at "+to.Name+" already has the email "+emailInOrg(u.Email, to.Domain)+".")
		return
	case errors.Is(err, store.ErrPending):
		writeError(w, http.StatusConflict, "pending", "There's already a request to move "+u.Name+".")
		return
	case errors.Is(err, store.ErrMoveOrganisation):
		writeFieldError(w, "domain", "There's no organisation we can move them to with that domain.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	}
	slog.Info("account move requested", "user", u.ID, "from", organisation(r).ID, "to", to.ID, "by", caller(r).ID)
	summary := u.Email + " → " + m.NewEmail
	a.auditIn(r, m.FromOrganisationID, store.ActionMoveRequested, aboutUser(u), "To "+to.Name+": "+summary)
	a.auditIn(r, m.ToOrganisationID, store.ActionMoveRequested, aboutUser(u), "From "+m.FromOrganisationName+": "+summary)
	a.notifyAdmins(r.Context(), to, "warning", "Request to move "+u.Name+" to "+to.Name,
		organisation(r).Name+" wants to move "+u.Name+" ("+u.Email+") to "+to.Name+", as "+m.NewEmail+". Accept or decline.",
		orgLink(to)+"/users")
	_ = a.store.Notify(r.Context(), []string{u.ID}, "info", "Your account may move to "+to.Name,
		organisation(r).Name+" asked to move your account to "+to.Name+". If "+to.Name+" accepts, your email will change to "+
			m.NewEmail+" and you'll be signed out.", "")
	writeJSON(w, http.StatusCreated, m)
}

// POST …/moves/{moveID}/accept, /decline (the receiving organisation) or
// /cancel (the organisation that asked).
func (a *API) decideMove(w http.ResponseWriter, r *http.Request) {
	if !a.needGlobalAdmin(w, r) {
		return
	}
	org := organisation(r)
	by := caller(r)
	decision := chi.URLParam(r, "decision")
	if decision == "cancel" {
		m, err := a.store.MoveByID(r.Context(), chi.URLParam(r, "moveID"))
		if err != nil || m.FromOrganisationID != org.ID {
			writeError(w, http.StatusNotFound, "not_found", "That request doesn't exist.")
			return
		}
		ok, err := a.store.CancelMove(r.Context(), m.ID, org.ID, by)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !ok {
			writeError(w, http.StatusConflict, "decided", "That request has already been answered.")
			return
		}
		t := about{store.TargetUser, m.UserID, m.UserName}
		a.auditIn(r, m.FromOrganisationID, store.ActionMoveCancelled, t, "Cancelled the move to "+m.ToOrganisationName)
		a.auditIn(r, m.ToOrganisationID, store.ActionMoveCancelled, t, m.FromOrganisationName+" cancelled the move of "+m.UserName)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	accept := decision == "accept"
	m, ok, err := a.store.DecideMove(r.Context(), chi.URLParam(r, "moveID"), org.ID, accept, by)
	switch {
	case errors.Is(err, store.ErrMoveEmailTaken):
		writeError(w, http.StatusConflict, "email_taken", "Someone in "+org.Name+" now has that email, so the account can't move.")
		return
	case errors.Is(err, store.ErrMoveLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", "They're now the only global admin of "+"their organisation, so the account can't move.")
		return
	case errors.Is(err, store.ErrMoveNotAllowed), errors.Is(err, store.ErrMoveOrganisation):
		writeError(w, http.StatusConflict, "not_movable", "This account can't be moved any more. Decline the request.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	case !ok:
		writeError(w, http.StatusNotFound, "not_found", "That request isn't waiting for you.")
		return
	}
	t := about{store.TargetUser, m.UserID, m.UserName}
	if accept {
		slog.Info("account moved", "user", m.UserID, "from", m.FromOrganisationID, "to", m.ToOrganisationID, "by", by.ID)
		summary := m.OldEmail + " → " + m.NewEmail
		a.auditIn(r, m.FromOrganisationID, store.ActionMoveAccepted, t, m.ToOrganisationName+" accepted. "+summary)
		a.auditIn(r, m.ToOrganisationID, store.ActionMoveAccepted, t, "Accepted from "+m.FromOrganisationName+". "+summary)
		_ = a.store.Notify(r.Context(), []string{m.UserID}, "success", "Your account is now at "+m.ToOrganisationName,
			"Your email is now "+m.NewEmail+". Sign in again with it.", "")
		a.notifyAdmins(r.Context(), &store.Organisation{ID: m.FromOrganisationID}, "success", m.UserName+" moved",
			m.ToOrganisationName+" accepted "+m.UserName+". Their email is now "+m.NewEmail+".", "/organisations/"+m.FromOrganisationID+"/users")
	} else {
		a.auditIn(r, m.FromOrganisationID, store.ActionMoveDeclined, t, m.ToOrganisationName+" declined to take "+m.UserName)
		a.auditIn(r, m.ToOrganisationID, store.ActionMoveDeclined, t, "Declined "+m.UserName+" from "+m.FromOrganisationName)
		a.notifyAdmins(r.Context(), &store.Organisation{ID: m.FromOrganisationID}, "info", "Move of "+m.UserName+" declined",
			m.ToOrganisationName+" declined to take "+m.UserName+".", "/organisations/"+m.FromOrganisationID+"/users")
	}
	writeJSON(w, http.StatusOK, m)
}

// emailInOrg: the same username at another domain.
func emailInOrg(email, domain string) string {
	local, _, _ := strings.Cut(email, "@")
	return local + "@" + domain
}
