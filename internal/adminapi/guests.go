package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/principal"
	"github.com/thekestongroup/id/internal/store"
)

// Guests (store/guests.go): people from other organisations who work in
// Keston Admin as members of this one. Their home organisation keeps their
// account, password, MFA, deletion and apps; this organisation only decides
// their groups and admin roles here.
//
// The endpoints for the invited person (invitations, leaving, "my
// organisations", pop-ups) are the same for Keston Admin and for Keston ID's
// account pages, which reach /v1 with the session cookie.

// ── The person invited ───────────────────────────────────────────────────

// guestCaller: the caller, as a guest in org: a plain member of it with
// what its groups and roles give them. Every handler under /organisations/
// {orgID} then works the same as for the organisation's own people, with
// the guest's own account details never reaching it (only home accounts are
// ever targets, see target).
func guestCaller(c *principal.Caller, org *store.Organisation, perms store.Perms) *principal.Caller {
	u := *c.User
	u.OrganisationID, u.Organisation, u.OrganisationVerified = org.ID, org.Name, org.Verified
	u.Role, u.PlatformAdmin = "member", false
	out := *c
	out.User, out.Perms = &u, perms
	return &out
}

type myOrganisation struct {
	store.MyOrganisation
	// They have some permission in Keston Admin there.
	CanManage bool `json:"canManage"`
}

// GET /my-organisations: the organisations they can open in Keston Admin:
// home, then the ones they're a guest in. TKG Admins can also browse every
// organisation (GET /organisations).
func (a *API) myOrganisations(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	list, err := a.store.MyOrganisations(r.Context(), u)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]myOrganisation, len(list))
	for i, o := range list {
		perms, err := a.store.PermissionsIn(r.Context(), u, o.ID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		out[i] = myOrganisation{o, len(perms) > 0}
	}
	writeJSON(w, http.StatusOK, map[string]any{"organisations": out, "canBrowseAll": u.PlatformAdmin})
}

// GET /guest-invitations: invitations waiting for the caller.
func (a *API) guestInvitations(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.InvitationsFor(r.Context(), caller(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// GET /guest-memberships: the organisations the caller is a guest in.
func (a *API) guestMemberships(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.GuestMembershipsOf(r.Context(), caller(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// POST /guest-invitations/{id}/accept or /decline.
func (a *API) respondToInvitation(w http.ResponseWriter, r *http.Request) {
	accept := chi.URLParam(r, "decision") == "accept"
	u := caller(r)
	g, err := a.store.RespondToInvitation(r.Context(), chi.URLParam(r, "id"), u.ID, accept)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That invitation isn't waiting for you any more.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	// Both organisations' logs: what the guest organisation's admins see,
	// and what the home organisation's do.
	action, verb := store.ActionGuestDeclined, "declined"
	if accept {
		action, verb = store.ActionGuestAccepted, "accepted"
	}
	summary := u.Name + " " + verb + " the invitation to be a guest in " + g.OrganisationName
	a.auditGuest(r, g, action, summary)
	if g.InvitedBy != nil {
		_ = a.store.Notify(r.Context(), []string{*g.InvitedBy}, map[bool]string{true: "success", false: "info"}[accept],
			u.Name+" "+verb+" your invitation", u.Name+" ("+u.Email+") "+verb+" the invitation to be a guest in "+
				g.OrganisationName+".", "/organisations/"+g.OrganisationID+"/users")
	}
	writeJSON(w, http.StatusOK, g)
}

// POST /guest-memberships/{id}/leave: stop being a guest.
func (a *API) leaveGuest(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	g, err := a.store.GuestByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil || g.UserID != u.ID || (g.Status != "accepted" && g.Status != "pending") {
		writeError(w, http.StatusNotFound, "not_found", "You're not a guest there.")
		return
	}
	if err := a.store.EndGuest(r.Context(), g); err != nil {
		serverError(w, r, err)
		return
	}
	a.auditGuest(r, g, store.ActionGuestLeft, u.Name+" left "+g.OrganisationName+" as a guest")
	a.notifyAdmins(r.Context(), &store.Organisation{ID: g.OrganisationID}, "info", u.Name+" left as a guest",
		u.Name+" ("+u.Email+") isn't a guest in "+g.OrganisationName+" any more.", "/organisations/"+g.OrganisationID+"/users")
	w.WriteHeader(http.StatusNoContent)
}

// auditGuest records a guest change in both organisations' logs (the guest
// organisation's admins and the home organisation's admins each see it).
func (a *API) auditGuest(r *http.Request, g *store.Guest, action, summary string) {
	t := about{store.TargetUser, g.UserID, g.UserName}
	a.auditIn(r, g.OrganisationID, action, t, summary)
	if g.HomeOrganisationID != g.OrganisationID {
		a.auditIn(r, g.HomeOrganisationID, action, t, summary)
	}
}

// ── One-time pop-ups ─────────────────────────────────────────────────────

const (
	promptInvitation = "guest_invitation"
	promptMove       = "account_move"
)

type promptInvitationJSON struct {
	store.Guest
	// Not shown as a pop-up yet.
	Popup bool `json:"popup"`
}

type promptMoveJSON struct {
	store.AccountMove
	Popup bool `json:"popup"`
}

// GET /prompts: what needs the caller's answer: guest invitations, and
// (for global admins) requests to move an account into their organisation.
// popup is true the first time, so each pop-up appears once.
func (a *API) prompts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := caller(r)
	invites, err := a.store.InvitationsFor(ctx, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	seen, err := a.store.PromptsSeen(ctx, u.ID, promptInvitation)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := struct {
		GuestInvitations []promptInvitationJSON `json:"guestInvitations"`
		MoveRequests     []promptMoveJSON       `json:"moveRequests"`
	}{[]promptInvitationJSON{}, []promptMoveJSON{}}
	for _, g := range invites {
		out.GuestInvitations = append(out.GuestInvitations, promptInvitationJSON{g, !seen[g.ID]})
	}
	if decides(u, u.OrganisationID) {
		moves, err := a.store.PendingMovesTo(ctx, u.OrganisationID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		seen, err := a.store.PromptsSeen(ctx, u.ID, promptMove)
		if err != nil {
			serverError(w, r, err)
			return
		}
		for _, m := range moves {
			out.MoveRequests = append(out.MoveRequests, promptMoveJSON{m, !seen[m.ID]})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /prompts/seen {kind, id}: the pop-up was shown.
func (a *API) promptSeen(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Kind != promptInvitation && body.Kind != promptMove {
		writeFieldError(w, "kind", "Unknown pop-up")
		return
	}
	if err := a.store.MarkPromptSeen(r.Context(), caller(r).ID, body.Kind, body.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── The organisation's guests ────────────────────────────────────────────

// GET …/guests: pending invitations and guests.
func (a *API) listGuests(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.GuestsInOrganisation(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// A guest organisation's admins learn which organisation a guest is
	// from (their email says so already), and nothing else about it.
	writeJSON(w, http.StatusOK, list)
}

// The one message for an invitation that can't be delivered: the same
// whether nobody has that address or their organisation doesn't allow
// guests, so the inviter learns nothing about who has an account.
const undeliverable = "We couldn't deliver that invitation. Check the email address. If it's right, the person's organisation doesn't let its people be guests in other organisations."

// POST …/guests {email}: invite someone from another organisation to be a
// guest here. Needs "Add users".
func (a *API) inviteGuest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &body) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.Contains(email, "@") || len(email) > 254 {
		writeFieldError(w, "email", "Enter their email address")
		return
	}
	org := organisation(r)
	g, err := a.store.InviteGuest(r.Context(), org, email, caller(r))
	switch {
	case errors.Is(err, store.ErrGuestUndeliverable):
		writeError(w, http.StatusUnprocessableEntity, "guest_undeliverable", undeliverable)
		return
	case errors.Is(err, store.ErrGuestSameOrganisation):
		writeFieldError(w, "email", "They're already part of "+org.Name+".")
		return
	case errors.Is(err, store.ErrGuestExists):
		writeError(w, http.StatusConflict, "guest_exists", "They're already a guest here, or have an invitation waiting.")
		return
	case err != nil:
		serverError(w, r, err)
		return
	}
	slog.Info("guest invited", "organisation", org.ID, "user", g.UserID, "by", caller(r).ID)
	_ = a.store.Notify(r.Context(), []string{g.UserID}, "info", "Invitation to "+org.Name,
		caller(r).Name+" invited you to be a guest in "+org.Name+". Accept or decline.", "/invitations")
	a.auditGuest(r, g, store.ActionGuestInvited, "Invited "+g.UserName+" ("+g.UserEmail+") to be a guest in "+org.Name)
	writeJSON(w, http.StatusCreated, g)
}

// guest is the membership in the URL, in this organisation.
func (a *API) guest(w http.ResponseWriter, r *http.Request) *store.Guest {
	g, err := a.store.GuestByID(r.Context(), chi.URLParam(r, "guestID"))
	if err != nil || g.OrganisationID != organisation(r).ID || (g.Status != "accepted" && g.Status != "pending") {
		writeError(w, http.StatusNotFound, "not_found", "That guest doesn't exist.")
		return nil
	}
	return g
}

// DELETE …/guests/{guestID}: remove a guest, or withdraw an invitation.
// Needs "Delete users". Only this organisation's side of things goes: the
// person's account is untouched.
func (a *API) removeGuest(w http.ResponseWriter, r *http.Request) {
	g := a.guest(w, r)
	if g == nil {
		return
	}
	if err := a.store.EndGuest(r.Context(), g); err != nil {
		serverError(w, r, err)
		return
	}
	verb := "Removed guest "
	if g.Status == "pending" {
		verb = "Withdrew the invitation to "
	}
	a.auditGuest(r, g, store.ActionGuestRemoved, verb+g.UserName+" ("+g.UserEmail+") in "+organisation(r).Name)
	if g.Status == "accepted" {
		_ = a.store.Notify(r.Context(), []string{g.UserID}, "info", "Removed from "+organisation(r).Name,
			"You're not a guest in "+organisation(r).Name+" any more.", "")
	}
	w.WriteHeader(http.StatusNoContent)
}

// PUT …/guests/{guestID}/roles {roles}: the admin roles a guest has in this
// organisation. Needs "Give permissions", and every permission of the roles.
func (a *API) putGuestRoles(w http.ResponseWriter, r *http.Request) {
	g := a.guest(w, r)
	if g == nil {
		return
	}
	if g.Status != "accepted" {
		writeError(w, http.StatusConflict, "pending", "They haven't accepted the invitation yet.")
		return
	}
	var body struct {
		Roles []string `json:"roles"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Roles == nil {
		body.Roles = []string{}
	}
	if !checkRoles(w, r, append(append([]string{}, body.Roles...), g.AdminRoles...)) {
		return
	}
	added, removed, err := a.store.SetGuestRoles(r.Context(), g, body.Roles)
	if errors.Is(err, store.ErrNotFound) {
		writeFieldError(w, "roles", "Choose from the admin roles")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	parts := []string{}
	if len(added) > 0 {
		parts = append(parts, "Added: "+roleLabels(added))
	}
	if len(removed) > 0 {
		parts = append(parts, "Removed: "+roleLabels(removed))
	}
	if len(parts) > 0 {
		a.audit(r, store.ActionGuestRoles, about{store.TargetUser, g.UserID, g.UserName}, strings.Join(parts, ". "))
	}
	fresh, err := a.store.GuestByID(r.Context(), g.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, fresh)
}

// ── The setting ──────────────────────────────────────────────────────────

// GET …/guest-settings.
func (a *API) getGuestSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"allowGuests": organisation(r).AllowGuests})
}

// applyAllowGuests turns guests on or off and records it. The guest settings
// and the security defaults share it.
func (a *API) applyAllowGuests(r *http.Request, on bool) error {
	org := organisation(r)
	if err := a.store.SetAllowGuests(r.Context(), org.ID, on); err != nil {
		return err
	}
	a.audit(r, store.ActionGuestSetting, aboutOrg(org),
		change("Allow users to be guests in other organisations", onOff(org.AllowGuests), onOff(on)))
	return nil
}

// PUT …/guest-settings {allowGuests}: whether this organisation's people can
// be guests in other organisations. Turning it off puts every guest
// membership of its people on hold (they come back if it's turned on
// again), and stops invitations reaching them. Needs the same permission as
// the rest of Security.
func (a *API) putGuestSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AllowGuests *bool `json:"allowGuests"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.AllowGuests == nil {
		writeFieldError(w, "allowGuests", "Choose on or off")
		return
	}
	if err := a.applyAllowGuests(r, *body.AllowGuests); err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowGuests": *body.AllowGuests})
}
