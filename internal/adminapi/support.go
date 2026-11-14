package adminapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/store"
)

// ── Keston support access ────────────────────────────────────────────────

// GET …/support: whether Keston support has access now, and the requests.
func (a *API) getSupport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := organisation(r)
	until, err := a.store.SupportAccess(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	requests, err := a.store.SupportRequests(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	lockouts, err := a.store.LockoutRequests(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access":    map[string]any{"active": until != nil, "until": until},
		"requests":  requests,
		"lockouts":  lockouts,
		"canManage": a.canManage(ctx, caller(r), org.ID),
	})
}

func reason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &body) {
		return "", false
	}
	text := strings.TrimSpace(body.Reason)
	if text == "" || len(text) > 1000 {
		writeFieldError(w, "reason", "Say why, so the organisation's admins can decide")
		return "", false
	}
	return text, true
}

// notifyAdmins tells every global admin of the organisation.
func (a *API) notifyAdmins(ctx context.Context, org *store.Organisation, kind, title, body, link string) {
	admins, err := a.store.GlobalAdmins(ctx, org.ID)
	if err != nil {
		slog.Warn("notify admins", "error", err)
		return
	}
	ids := make([]string, len(admins))
	for i, u := range admins {
		ids[i] = u.ID
	}
	if err := a.store.Notify(ctx, ids, kind, title, body, link); err != nil {
		slog.Warn("notify admins", "error", err)
	}
}

func orgLink(org *store.Organisation) string { return "/organisations/" + org.ID }

// POST …/support/requests {reason}: Keston support asks for access.
func (a *API) requestSupport(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	if !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only Keston support asks for support access.")
		return
	}
	text, ok := reason(w, r)
	if !ok {
		return
	}
	id, err := a.store.RequestSupport(r.Context(), org.ID, u.ID, text)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.notifyAdmins(r.Context(), org, "warning", "Keston support is asking for access",
		u.Name+" from Keston support asked to see "+org.Name+"'s accounts: “"+text+"”. Approve or deny it in Keston Admin.",
		orgLink(org))
	slog.Info("support access requested", "organisation", org.ID, "request", id, "by", u.ID)
	w.WriteHeader(http.StatusCreated)
}

// POST …/support/requests/{id}/approve {days} or …/deny: the organisation's
// global admins decide.
func (a *API) decideSupport(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	if !isOwnAdmin(u, org.ID) {
		writeError(w, http.StatusForbidden, "forbidden", "Only "+org.Name+"'s global admins can decide.")
		return
	}
	approve := chi.URLParam(r, "decision") == "approve"
	var body struct {
		Days int `json:"days"`
	}
	_ = decodeOptional(r, &body)
	days := min(max(body.Days, 1), 30)
	if body.Days == 0 {
		days = 7
	}
	ok, err := a.store.DecideSupport(r.Context(), org.ID, chi.URLParam(r, "requestID"), u.ID, approve,
		time.Duration(days)*24*time.Hour)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "decided", "That request has already been decided.")
		return
	}
	verb := "denied"
	if approve {
		verb = fmt.Sprintf("approved for %d days", days)
	}
	a.notifyAdmins(r.Context(), org, "info", "Keston support access "+verb, u.Name+" "+verb+" Keston support's access.",
		orgLink(org))
	slog.Info("support access decided", "organisation", org.ID, "approved", approve, "by", u.ID)
	w.WriteHeader(http.StatusNoContent)
}

// POST …/support/revoke: a global admin ends support access early.
func (a *API) revokeSupport(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	if !isOwnAdmin(u, org.ID) {
		writeError(w, http.StatusForbidden, "forbidden", "Only "+org.Name+"'s global admins can end it.")
		return
	}
	if err := a.store.RevokeSupport(r.Context(), org.ID, u.ID); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("support access revoked", "organisation", org.ID, "by", u.ID)
	w.WriteHeader(http.StatusNoContent)
}

// ── Organisation lockout procedure ───────────────────────────────────────

// POST …/lockout {reason}: Keston support starts it, when nobody at the
// organisation can get in. Every global admin is told; unless one denies it
// within 3 days, support access is granted.
func (a *API) startLockout(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	if !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only Keston support starts the lockout procedure.")
		return
	}
	text, ok := reason(w, r)
	if !ok {
		return
	}
	l, err := a.store.StartLockout(r.Context(), org.ID, u.ID, text)
	if errors.Is(err, store.ErrPending) {
		writeError(w, http.StatusConflict, "pending", "A lockout request for "+org.Name+" is already waiting.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.notifyAdmins(r.Context(), org, "error", "An organisation lockout request has been made",
		fmt.Sprintf("Keston support was told nobody at %s can sign in: “%s”. Unless a global admin denies it by %s, "+
			"Keston support will be given access to restore it.", org.Name, text,
			l.EffectiveAt.Format("15:04 on 2 January 2006 (MST)")),
		orgLink(org))
	slog.Info("lockout procedure started", "organisation", org.ID, "lockout", l.ID, "by", u.ID)
	writeJSON(w, http.StatusCreated, l)
}

// POST …/lockout/{id}/deny (a global admin) or …/cancel (Keston support).
func (a *API) decideLockout(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org := organisation(r)
	decision := chi.URLParam(r, "decision")
	if decision == "deny" && !isOwnAdmin(u, org.ID) {
		writeError(w, http.StatusForbidden, "forbidden", "Only "+org.Name+"'s global admins can deny it.")
		return
	}
	if decision == "cancel" && !u.PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only Keston support can cancel it.")
		return
	}
	status := map[string]string{"deny": "denied", "cancel": "cancelled"}[decision]
	ok, err := a.store.DecideLockout(r.Context(), org.ID, chi.URLParam(r, "lockoutID"), u.ID, status)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		writeError(w, http.StatusConflict, "decided", "That request has already been decided, or has gone through.")
		return
	}
	a.notifyAdmins(r.Context(), org, "info", "Organisation lockout request "+status,
		u.Name+" "+status+" the lockout request. Keston support won't be given access by it.", orgLink(org))
	slog.Info("lockout procedure decided", "organisation", org.ID, "status", status, "by", u.ID)
	w.WriteHeader(http.StatusNoContent)
}

// Housekeeping finishes lockout requests nobody denied, and says so. Run
// regularly (every replica may; each request completes once).
func (a *API) Housekeeping(ctx context.Context) {
	done, err := a.store.CompleteDueLockouts(ctx)
	if err != nil {
		slog.Warn("lockout housekeeping", "error", err)
		return
	}
	for _, d := range done {
		org, err := a.store.OrganisationByID(ctx, d.OrganisationID)
		if err != nil {
			continue
		}
		a.notifyAdmins(ctx, org, "warning", "Keston support now has access",
			"Nobody denied the organisation lockout request, so Keston support can now restore access to "+
				org.Name+" for 7 days. A global admin can end it at any time.", orgLink(org))
		if d.RequestedBy != nil {
			_ = a.store.Notify(ctx, []string{*d.RequestedBy}, "success", "Lockout request for "+org.Name+" went through",
				"You have support access for 7 days.", orgLink(org))
		}
		slog.Info("lockout procedure completed", "organisation", org.ID, "lockout", d.ID)
	}
}

// ── Notifications ────────────────────────────────────────────────────────

func (a *API) notifications(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.Notifications(r.Context(), caller(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) readNotifications(w http.ResponseWriter, r *http.Request) {
	if err := a.store.MarkNotificationsRead(r.Context(), caller(r).ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) clearNotifications(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeleteNotifications(r.Context(), caller(r).ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
