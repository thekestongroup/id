package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thekestongroup/id/internal/store"
)

// signedInFully runs once someone has finished signing in (password and, if
// on, MFA). A global admin signing in cancels their organisation's pending
// deletion: that's how a deletion nobody wanted gets undone.
func (a *API) signedInFully(ctx context.Context, u *store.User) {
	if u.Role != "global_admin" || u.IsSupport() {
		return
	}
	cancelled, err := a.store.CancelDeletion(ctx, u.OrganisationID)
	if err != nil {
		slog.Warn("cancelling deletion on sign-in", "error", err)
		return
	}
	if !cancelled {
		return
	}
	slog.Info("organisation deletion cancelled by sign-in", "organisation", u.OrganisationID, "user", u.ID)
	a.store.Audit(ctx, store.AuditEntry{OrganisationID: u.OrganisationID, Actor: u,
		Action: store.ActionDeletionCancelled, TargetType: store.TargetOrganisation, TargetID: u.OrganisationID,
		TargetName: u.Organisation, Summary: "Cancelled by signing in"})
	admins, err := a.store.GlobalAdmins(ctx, u.OrganisationID)
	if err != nil {
		return
	}
	ids := make([]string, len(admins))
	for i, ad := range admins {
		ids[i] = ad.ID
	}
	_ = a.store.Notify(ctx, ids, "info", "Deletion cancelled",
		u.Name+" signed in, so "+u.Organisation+" won't be deleted.", "/organisations/"+u.OrganisationID)
}

// SupportSignIn (GET /support-sign-in?token=…) opens a Keston support
// account: Keston Admin sends Keston staff here with a sealed, 60-second
// token for their support account in another organisation. It's added to
// this browser's signed-in accounts (alongside their own) as the active one,
// then they go back to Keston Admin as it.
func (a *API) SupportSignIn(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		http.Error(w, msg+" Go back to Keston Admin and try again.", http.StatusBadRequest)
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("token"))
	if err != nil {
		fail("That link isn't right.")
		return
	}
	plain, err := a.store.Box.Open(raw)
	if err != nil {
		fail("That link isn't right.")
		return
	}
	var h struct {
		SupportUser string `json:"s"`
		Staff       string `json:"f"`
		Org         string `json:"o"`
		Expires     int64  `json:"e"`
	}
	if json.Unmarshal(plain, &h) != nil || time.Now().Unix() > h.Expires {
		fail("That link has expired.")
		return
	}
	ctx := r.Context()
	staff, err := a.store.UserByID(ctx, h.Staff)
	if err != nil || !staff.PlatformAdmin || !staff.Usable() {
		fail("Only Keston support can open support accounts.")
		return
	}
	sa, err := a.store.UserByID(ctx, h.SupportUser)
	if err != nil || sa.SupportFor == nil || *sa.SupportFor != staff.ID || !sa.Usable() {
		if err == nil && sa.SupportFor != nil && *sa.SupportFor == staff.ID {
			a.logSignIn(r, store.SignIn{User: sa, Method: store.SignInSupport, Staff: staff, Reason: failReason(sa)})
		}
		fail("Support access has ended.")
		return
	}
	token, _, err := a.store.CreateSession(ctx, sa.ID, "verified", []string{"support"}, r.UserAgent(), clientIP(r),
		time.Until(*sa.ExpiresAt))
	if err != nil {
		slog.Error("support sign-in", "error", err)
		http.Error(w, "Something went wrong.", http.StatusInternalServerError)
		return
	}
	a.addSession(w, r, token, sa.ID)
	a.logSignIn(r, store.SignIn{User: sa, Method: store.SignInSupport, Staff: staff, Success: true})
	slog.Info("support account signed in", "support_user", sa.ID, "staff", staff.ID, "organisation", h.Org)
	// Back to Keston Admin (admin.… next to id.…), which signs in as it.
	admin := strings.Replace(a.cfg.Issuer, "//id.", "//admin.", 1)
	http.Redirect(w, r, admin+"/support-handoff?org="+url.QueryEscape(h.Org), http.StatusSeeOther)
}
