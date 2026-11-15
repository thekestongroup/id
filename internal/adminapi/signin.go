package adminapi

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// ── Sign-in requirements ─────────────────────────────────────────────────
//
// What someone must do when they next sign in (see api/required.go):
// choose a new password, set up MFA. And temporary access passes, to sign
// in without a password or MFA (e.g. after losing a phone).

// GET …/mfa-policy: whether MFA is required, by default and per group.
func (a *API) getMFAPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := a.store.MFAPolicy(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// PUT …/mfa-policy {mode?, gracePeriodDays?, required?}: any of the
// organisation's MFA mode (off, required, custom), the grace period for
// "required" (0–90 days), and the custom rules' default. Changes apply at
// each person's next sign-in.
func (a *API) putMFAPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode            *string `json:"mode"`
		GracePeriodDays *int    `json:"gracePeriodDays"`
		Required        *bool   `json:"required"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Mode != nil && !slices.Contains([]string{store.MFAOff, store.MFARequired, store.MFACustom}, *body.Mode) {
		writeFieldError(w, "mode", "Choose Off, Require MFA for everyone or Custom rules")
		return
	}
	if body.GracePeriodDays != nil && (*body.GracePeriodDays < 0 || *body.GracePeriodDays > 90) {
		writeFieldError(w, "gracePeriodDays", "Enter a number of days from 0 to 90")
		return
	}
	ctx := r.Context()
	org := organisation(r)
	before, err := a.store.MFAPolicy(ctx, org.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	changes := []string{}
	if body.Mode != nil && *body.Mode != before.Mode {
		if err := a.store.SetMFAMode(ctx, org.ID, *body.Mode); err != nil {
			serverError(w, r, err)
			return
		}
		changes = append(changes, change("Multi-factor authentication", mfaModeLabel(before.Mode), mfaModeLabel(*body.Mode)))
	}
	if body.GracePeriodDays != nil && *body.GracePeriodDays != before.GracePeriodDays {
		if err := a.store.SetMFAGraceDays(ctx, org.ID, *body.GracePeriodDays); err != nil {
			serverError(w, r, err)
			return
		}
		changes = append(changes, change("Grace period", days(before.GracePeriodDays), days(*body.GracePeriodDays)))
	}
	if body.Required != nil && *body.Required != before.Required {
		if err := a.store.SetMFARequired(ctx, org.ID, *body.Required); err != nil {
			serverError(w, r, err)
			return
		}
		changes = append(changes, "Everyone else: "+requiredLabel(body.Required))
	}
	if len(changes) > 0 {
		slog.Info("mfa policy changed", "organisation", org.ID, "changes", changes, "by", caller(r).ID)
		a.audit(r, store.ActionMFAPolicy, aboutOrg(org), strings.Join(changes, ". "))
	}
	a.getMFAPolicy(w, r)
}

func mfaModeLabel(mode string) string {
	return map[string]string{store.MFAOff: "Off", store.MFARequired: "Required for everyone",
		store.MFACustom: "Custom rules"}[mode]
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func requiredLabel(v *bool) string {
	switch {
	case v == nil:
		return "Use the default"
	case *v:
		return "MFA required"
	}
	return "MFA not required"
}

// PUT …/mfa-policy/groups/{groupID} {required: true|false|null}: a group's
// setting; null uses the default.
func (a *API) putGroupMFAPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Required *bool `json:"required"`
	}
	if !decode(w, r, &body) {
		return
	}
	err := a.store.SetGroupMFARequired(r.Context(), organisation(r).ID, chi.URLParam(r, "groupID"), body.Required)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That group doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("group mfa requirement changed", "organisation", organisation(r).ID,
		"group", chi.URLParam(r, "groupID"), "by", caller(r).ID)
	if g, err := a.store.Group(r.Context(), organisation(r).ID, chi.URLParam(r, "groupID")); err == nil {
		a.audit(r, store.ActionMFAPolicy, aboutGroup(g), g.Name+": "+requiredLabel(body.Required))
	}
	a.getMFAPolicy(w, r)
}

type accessPassJSON struct {
	store.AccessPass
	// Can still be used to sign in.
	Active bool `json:"active"`
}

func viewPasses(list []store.AccessPass) []accessPassJSON {
	out := make([]accessPassJSON, len(list))
	for i, p := range list {
		out[i] = accessPassJSON{p, p.Usable(nowFunc())}
	}
	return out
}

// GET …/users/{id}/sign-in: what they must do at their next sign-in, and
// their access passes (from the last week; never the codes).
func (a *API) getSignIn(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	ctx := r.Context()
	st, err := a.store.SignInState(ctx, u)
	if err != nil {
		serverError(w, r, err)
		return
	}
	passes, err := a.store.AccessPasses(ctx, u.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"passwordChangeRequired": st.PasswordChangeRequired,
		"mfaRequired":            st.MFARequired,
		"accessPasses":           viewPasses(passes),
	})
}

// POST …/users/{id}/require-password-change {required}: they choose a new
// password next time they sign in (or not any more).
func (a *API) requirePasswordChange(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	body := struct {
		Required *bool `json:"required"`
	}{}
	if err := decodeOptional(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return
	}
	required := body.Required == nil || *body.Required
	if err := a.store.SetPasswordChangeRequired(r.Context(), u.ID, required); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("password change requirement set", "user", u.ID, "required", required, "by", caller(r).ID)
	if required {
		a.audit(r, store.ActionPasswordChangeSet, aboutUser(u), "At their next sign-in")
	} else {
		a.audit(r, store.ActionPasswordChangeSet, aboutUser(u), "No longer required")
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST …/users/{id}/access-passes {oneTime, hours, requirePasswordChange}:
// a new pass, valid for 1–8 hours (one-time: once in that time). The code
// is in this response only.
func (a *API) createAccessPass(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body struct {
		OneTime               bool `json:"oneTime"`
		Hours                 int  `json:"hours"`
		RequirePasswordChange bool `json:"requirePasswordChange"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Hours < 1 || body.Hours > 8 {
		writeFieldError(w, "hours", "Choose between 1 and 8 hours")
		return
	}
	if u.Status != "active" {
		writeError(w, http.StatusConflict, "disabled", u.Name+" is disabled. Enable them first.")
		return
	}
	ctx := r.Context()
	code, hash := secret.NewAccessPass()
	pass, err := a.store.CreateAccessPass(ctx, u.ID, caller(r).ID, hash, body.OneTime,
		time.Duration(body.Hours)*time.Hour)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if body.RequirePasswordChange {
		if err := a.store.SetPasswordChangeRequired(ctx, u.ID, true); err != nil {
			serverError(w, r, err)
			return
		}
	}
	slog.Info("access pass issued", "user", u.ID, "pass", pass.ID, "oneTime", body.OneTime, "hours", body.Hours,
		"by", caller(r).ID)
	kind := "Reusable"
	if body.OneTime {
		kind = "One-time"
	}
	a.audit(r, store.ActionAccessPassIssued, aboutUser(u), fmt.Sprintf("%s, for %d hours", kind, body.Hours))
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "pass": accessPassJSON{*pass, true}})
}

// DELETE …/users/{id}/access-passes/{passID}: it stops working.
func (a *API) revokeAccessPass(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	err := a.store.RevokeAccessPass(r.Context(), u.ID, chi.URLParam(r, "passID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That access pass doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("access pass revoked", "user", u.ID, "pass", chi.URLParam(r, "passID"), "by", caller(r).ID)
	a.audit(r, store.ActionAccessPassRevoked, aboutUser(u), "")
	w.WriteHeader(http.StatusNoContent)
}
