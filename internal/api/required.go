package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"rsc.io/qr"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// ── Required actions ─────────────────────────────────────────────────────
//
// After the password (and MFA, or an access pass) and before consent and
// the app, someone may have to:
//   - "password": choose a new password (an admin asked them to)
//   - "mfa": set up MFA (their organisation or a group requires it, or they
//     signed in with an access pass)
//
// Until they're done the session is in the 'actions' stage: not fully
// verified, so no tokens and no account pages. A verified session that
// gains an action (an admin requires it later) goes back to 'actions' the
// next time it's used.

const (
	ActionPassword = "password"
	ActionMFA      = "mfa"
)

// amrAccessPass marks a session signed in with a temporary access pass.
const amrAccessPass = "tap"

// requiredActions: what's left for this session, in order.
func (a *API) requiredActions(ctx context.Context, cur *current) ([]string, error) {
	// Support accounts are opened by Keston staff from their own account,
	// which has its own password and MFA.
	if cur.user.IsSupport() {
		return nil, nil
	}
	st, err := a.store.SignInState(ctx, cur.user)
	if err != nil {
		return nil, err
	}
	out := []string{}
	if st.PasswordChangeRequired {
		out = append(out, ActionPassword)
	}
	// After an access pass, MFA is set up again (they may have lost their
	// phone), whatever was there before.
	viaPass := slices.Contains(cur.session.AMR, amrAccessPass) &&
		!slices.Contains(cur.session.AMR, "otp") && !slices.Contains(cur.session.AMR, "hwk")
	hasMFA, err := a.store.HasMFA(ctx, cur.user)
	if err != nil {
		return nil, err
	}
	switch {
	case viaPass:
		out = append(out, ActionMFA)
	case st.MFARequired && !hasMFA:
		// In the grace period, "Not now" puts it off for this session.
		if st.MFADeadline == nil || !time.Now().Before(*st.MFADeadline) || !cur.session.MFASkipped {
			out = append(out, ActionMFA)
		}
	}
	return out, nil
}

// mfaGraceUntil: when setting up MFA becomes compulsory for them, if they
// can still put it off ("Not now"); nil if they can't.
func (a *API) mfaGraceUntil(ctx context.Context, cur *current) *time.Time {
	if cur.user.IsSupport() || (slices.Contains(cur.session.AMR, amrAccessPass) &&
		!slices.Contains(cur.session.AMR, "otp") && !slices.Contains(cur.session.AMR, "hwk")) {
		return nil
	}
	st, err := a.store.SignInState(ctx, cur.user)
	if err != nil || st.MFADeadline == nil || !time.Now().Before(*st.MFADeadline) {
		return nil
	}
	return st.MFADeadline
}

// POST /api/required/mfa/skip {authRequestID}: "Not now", during the grace
// period. They're asked again next time they sign in.
func (a *API) requiredMFASkip(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := a.inActions(w, r, ActionMFA)
	if cur == nil {
		return
	}
	ctx := r.Context()
	if a.mfaGraceUntil(ctx, cur) == nil {
		writeError(w, http.StatusConflict, "required", "Your organisation requires MFA now. Set it up to continue.")
		return
	}
	if err := a.store.SkipMFAForNow(ctx, cur.session.ID); err != nil {
		serverError(w, r, err)
		return
	}
	cur.session.MFASkipped = true
	a.respondNext(w, r, cur, body.AuthRequestID)
}

// settle brings a signed-in session's stage up to date: 'actions' while any
// are left, 'verified' once there are none. It returns what's left.
func (a *API) settle(ctx context.Context, cur *current) ([]string, error) {
	if cur.session.Stage == store.StagePassword {
		return nil, nil
	}
	actions, err := a.requiredActions(ctx, cur)
	if err != nil {
		return nil, err
	}
	switch {
	case len(actions) > 0 && cur.session.Stage == store.StageVerified:
		if s, changed, err := a.store.SetSessionStage(ctx, cur.session.ID, store.StageVerified, store.StageActions); err != nil {
			return nil, err
		} else if changed {
			cur.session = s
		}
	case len(actions) == 0 && cur.session.Stage == store.StageActions:
		s, changed, err := a.store.SetSessionStage(ctx, cur.session.ID, store.StageActions, store.StageVerified)
		if err != nil {
			return nil, err
		}
		if changed {
			cur.session = s
			a.signedInFully(ctx, cur.user)
		}
	}
	return actions, nil
}

// inActions: the active session, if it's waiting on this action.
func (a *API) inActions(w http.ResponseWriter, r *http.Request, action string) *current {
	cur := a.current(r)
	if cur == nil || cur.session.Stage == store.StagePassword {
		writeError(w, http.StatusUnauthorized, "signed_out", "Sign in again to continue.")
		return nil
	}
	actions, err := a.settle(r.Context(), cur)
	if err != nil {
		serverError(w, r, err)
		return nil
	}
	if !slices.Contains(actions, action) {
		writeError(w, http.StatusConflict, "not_required", "You don't need to do that now.")
		return nil
	}
	return cur
}

// POST /api/required/password {new, authRequestID}: the new password they
// were asked to choose. It must meet their organisation's rules and differ
// from the old one. Every other device is signed out.
func (a *API) requiredPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		New           string `json:"new"`
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := a.inActions(w, r, ActionPassword)
	if cur == nil {
		return
	}
	ctx := r.Context()
	pol := a.store.PolicyFor(ctx, cur.user.OrganisationID)
	if failed := pol.Check(body.New, username(cur.user.Email)); len(failed) > 0 {
		writeFieldError(w, "new", policy.Message(failed))
		return
	}
	if same, err := secret.CheckPassword(cur.user.PasswordHash, body.New); err == nil && same {
		writeFieldError(w, "new", "Choose a different password from your old one")
		return
	}
	if err := a.store.SetRequiredPassword(ctx, cur.user.ID, secret.HashPassword(body.New)); err != nil {
		serverError(w, r, err)
		return
	}
	others, err := a.store.SessionsForUser(ctx, cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	for _, s := range others {
		if s.ID != cur.session.ID {
			a.end(ctx, s.ID)
		}
	}
	a.respondNext(w, r, a.reload(r, cur), body.AuthRequestID)
}

// POST /api/required/mfa/setup: a new authenticator secret, kept apart from
// any one in use until it's confirmed.
func (a *API) requiredMFASetup(w http.ResponseWriter, r *http.Request) {
	cur := a.inActions(w, r, ActionMFA)
	if cur == nil {
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Keston ID", AccountName: cur.user.Email})
	if err != nil {
		serverError(w, r, err)
		return
	}
	if err := a.store.SetPendingTOTP(r.Context(), cur.user.ID, a.store.Box.Seal([]byte(key.Secret()))); err != nil {
		serverError(w, r, err)
		return
	}
	code, err := qr.Encode(key.URL(), qr.M)
	if err != nil {
		serverError(w, r, err)
		return
	}
	code.Scale = 6
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":     key.Secret(),
		"otpauthUrl": key.URL(),
		"qrCode":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()),
	})
}

// POST /api/required/mfa/enable {code, authRequestID}: confirms the new
// authenticator, turns MFA on, and returns the backup codes (shown once)
// and where the flow goes next.
func (a *API) requiredMFAEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code          string `json:"code"`
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := a.inActions(w, r, ActionMFA)
	if cur == nil {
		return
	}
	ctx := r.Context()
	pending, err := a.store.PendingTOTP(ctx, cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if pending == nil {
		writeError(w, http.StatusConflict, "no_setup", "Start setting up MFA first.")
		return
	}
	key, err := a.store.Box.Open(pending)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !totp.Validate(strings.ReplaceAll(strings.TrimSpace(body.Code), " ", ""), string(key)) {
		writeFieldError(w, "code", "That code didn't work. Check the time on your phone and try again.")
		return
	}
	codes, hashes := backupCodes(10)
	if err := a.store.UsePendingTOTP(ctx, cur.user.ID, hashes); err != nil {
		serverError(w, r, err)
		return
	}
	sess, err := a.store.AddSessionMethod(ctx, cur.session.ID, "otp")
	if err != nil {
		serverError(w, r, err)
		return
	}
	cur.session = sess
	res, status, msg := a.next(r, a.reload(r, cur), body.AuthRequestID)
	if res == nil {
		writeError(w, status, "flow_error", msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backupCodes": codes, "flow": res})
}

// reload: the same session with the user as they are now.
func (a *API) reload(r *http.Request, cur *current) *current {
	if u, err := a.store.UserByID(r.Context(), cur.user.ID); err == nil {
		return &current{session: cur.session, user: u, token: cur.token}
	}
	return cur
}

// ── Temporary access passes ──────────────────────────────────────────────

// POST /api/sign-in/access-pass {email, code, authRequestID}: signing in
// with a pass from an admin instead of a password and MFA. They then set up
// MFA again (and a new password, if asked).
func (a *API) signInWithPass(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email         string `json:"email"`
		Code          string `json:"code"`
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	code := secret.NormaliseAccessPass(body.Code)
	if body.Email == "" {
		writeFieldError(w, "email", "Enter your email address")
		return
	}
	if code == "" {
		writeFieldError(w, "code", "Enter your access pass")
		return
	}
	const wrong = "Incorrect email or access pass, or the pass has expired"
	ctx := r.Context()
	user, err := a.store.UserByEmail(ctx, body.Email)
	if err != nil {
		if !isNotFound(err) {
			serverError(w, r, err)
			return
		}
		a.logSignIn(r, store.SignIn{Email: body.Email, Method: store.SignInAccessPass, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonUnknownUser})
		writeFieldError(w, "code", wrong)
		return
	}
	log := func(success bool, reason string) {
		a.logSignIn(r, store.SignIn{User: user, Method: store.SignInAccessPass, AuthRequestID: body.AuthRequestID,
			Success: success, Reason: reason})
	}
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		log(false, store.ReasonLocked)
		writeError(w, http.StatusTooManyRequests, "locked", "Too many attempts. Wait 15 minutes and try again.")
		return
	}
	if user.IsSupport() || !user.Usable() {
		why := store.ReasonSupportAccount
		if !user.IsSupport() {
			why = failReason(user)
		}
		log(false, why)
		writeFieldError(w, "code", wrong)
		return
	}
	ok, err := a.store.UseAccessPass(ctx, user.ID, secret.Hash(code))
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		_ = a.store.RecordLogin(ctx, user.ID, false)
		log(false, store.ReasonWrongPass)
		writeFieldError(w, "code", wrong)
		return
	}
	_ = a.store.RecordLogin(ctx, user.ID, true)
	log(true, "")
	token, sess, err := a.store.CreateSession(ctx, user.ID, store.StageActions, []string{amrAccessPass}, r.UserAgent(),
		clientIP(r), a.cfg.SessionTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.addSession(w, r, token, user.ID)
	if body.AuthRequestID != "" {
		_ = a.store.ChooseAccount(ctx, body.AuthRequestID)
	}
	a.respondNext(w, r, &current{session: sess, user: user, token: token}, body.AuthRequestID)
}
