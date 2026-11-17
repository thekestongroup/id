package api

import (
	"context"
	"github.com/thekestongroup/id/internal/clientip"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// flowResponse tells the web UI which page comes next.
//
//	step: "sign-in" | "choose" | "mfa" | "actions" | "consent" | "redirect" | "account"
type flowResponse struct {
	Step     string      `json:"step"`
	Redirect string      `json:"redirect,omitempty"`
	Client   *clientView `json:"client,omitempty"`
	Scopes   *struct {
		Required []ScopeInfo `json:"required"`
		Optional []ScopeInfo `json:"optional"`
	} `json:"scopes,omitempty"`
	User *userView `json:"user,omitempty"`
	// step "actions": what they must do first, in order ("password", "mfa").
	Actions []string `json:"actions,omitempty"`
	// Setting up MFA can be put off ("Not now") until then.
	MFAGraceUntil *time.Time `json:"mfaGraceUntil,omitempty"`
	// step "actions" with "password": what the new password must meet (the
	// organisation's policy), for the page to check as they type. The server
	// still checks it.
	PasswordRules []policy.Rule `json:"passwordRules,omitempty"`
	// At the MFA step: the ways this account can do it.
	MFA *mfaMethods `json:"mfa,omitempty"`
}

// next works out where someone goes from here: the heart of the sign-in flow.
// Without an auth request (signing in to Keston ID itself), it ends at the
// account page; with one, at the app.
func (a *API) next(r *http.Request, cur *current, authRequestID string) (*flowResponse, int, string) {
	ctx := r.Context()
	res := &flowResponse{}
	var actions []string
	if cur != nil {
		u := a.viewUser(cur.user)
		res.User = &u
		// Required actions (required.go): up to date before anything else.
		// Where they're signing in from and to, for MFA rules.
		sc := store.SignInContext{IP: clientip.From(r)}
		if authRequestID != "" {
			if ar, err := a.store.AuthRequestByID(ctx, authRequestID); err == nil {
				sc.ClientID = ar.ClientID
			}
		}
		var err error
		if actions, err = a.settle(ctx, cur, sc); err != nil {
			return nil, http.StatusInternalServerError, "Something went wrong. Try again."
		}
	}

	if authRequestID == "" {
		switch {
		case cur == nil:
			res.Step = "sign-in"
		case cur.session.Stage == store.StagePassword:
			res.Step = "mfa"
			res.MFA = a.mfaMethodsFor(ctx, cur.user)
		case len(actions) > 0:
			res.Step, res.Actions = "actions", actions
			res.MFAGraceUntil = a.graceFor(ctx, cur, actions)
			res.PasswordRules = a.rulesFor(ctx, cur, actions)
		default:
			res.Step = "account"
		}
		return res, 0, ""
	}

	ar, err := a.store.AuthRequestByID(ctx, authRequestID)
	if err != nil {
		return nil, http.StatusGone, "This sign-in link has expired. Go back to the app and try again."
	}
	client, err := a.store.ClientByID(ctx, ar.ClientID)
	if err != nil || client.RetiredAt != nil {
		return nil, http.StatusGone, "This app is no longer registered with Keston ID."
	}
	cv := viewClient(client, ar.RedirectURI)
	res.Client = &cv

	promptNone := slices.Contains(ar.Prompt, "none")
	needsLogin := cur == nil
	if cur != nil {
		// prompt=login: sign in again, even with a session.
		if slices.Contains(ar.Prompt, "login") && cur.session.AuthTime.Before(ar.CreatedAt) {
			needsLogin = true
		}
		// max_age: the sign-in must be recent enough, counted from when the
		// app asked (prompt=login arrives as max_age=0: a sign-in after that).
		if ar.MaxAgeSeconds != nil &&
			cur.session.AuthTime.Before(ar.CreatedAt.Add(-time.Duration(*ar.MaxAgeSeconds)*time.Second)) {
			needsLogin = true
		}
	}
	if needsLogin {
		if promptNone {
			res.Step, res.Redirect = "redirect", a.denyURL(ar.ID, "login_required")
			return res, 0, ""
		}
		res.Step = "sign-in"
		return res, 0, ""
	}
	// Several accounts signed in (or the app asks): which one?
	if !ar.AccountChosen && !promptNone &&
		(slices.Contains(ar.Prompt, "select_account") || len(a.signedIn(r)) > 1) {
		res.Step = "choose"
		return res, 0, ""
	}
	if cur.session.Stage == store.StagePassword {
		res.Step = "mfa"
		res.MFA = a.mfaMethodsFor(ctx, cur.user)
		return res, 0, ""
	}
	// Before consent and the app: a new password, MFA set up…
	if len(actions) > 0 {
		if promptNone {
			res.Step, res.Redirect = "redirect", a.denyURL(ar.ID, "interaction_required")
			return res, 0, ""
		}
		res.Step, res.Actions = "actions", actions
		res.MFAGraceUntil = a.graceFor(ctx, cur, actions)
		res.PasswordRules = a.rulesFor(ctx, cur, actions)
		return res, 0, ""
	}
	// Another organisation's own app: only its users can sign in to it.
	if client.OrganisationID != nil && *client.OrganisationID != cur.user.OrganisationID {
		return nil, http.StatusForbidden, client.Name + " is only for another organisation's accounts. " +
			"Sign in with your account there, or ask the app's admins."
	}
	// A Keston product they have no licence for (Keston Admin → Users).
	if ok, err := a.store.Licensed(ctx, cur.user, client.ID); err == nil && !ok {
		a.logSignIn(r, store.SignIn{User: cur.user, Method: store.SignInApp, ClientID: client.ID,
			Reason: store.ReasonNoLicence})
		return nil, http.StatusForbidden, "You don't have a licence for " + client.Name +
			". Ask one of " + cur.user.Organisation + "'s admins if you need it."
	}
	// Turned off for them by their organisation (Keston Admin → Apps).
	if eff, err := a.store.EffectiveAppsFrom(ctx, cur.user, clientip.From(r)); err == nil && eff[client.ID] == store.AppDisabled {
		a.logSignIn(r, store.SignIn{User: cur.user, Method: store.SignInApp, ClientID: client.ID,
			Reason: store.ReasonAppDisabled})
		return nil, http.StatusForbidden, cur.user.Organisation + " has turned off " + client.Name +
			" for your account. Ask one of its admins if you need it."
	}

	required := withoutOpenID(intersect(ar.Scopes, client.RequiredScopes))
	optional := withoutOpenID(intersect(ar.Scopes, client.OptionalScopes))

	// Already allowed (or one of Keston's own apps that skips the prompt):
	// straight back to the app. Optional scopes someone unticked before stay
	// unticked, rather than asking again.
	var granted []string
	if client.SkipConsent {
		granted = ar.Scopes
	} else if client.OrganisationID != nil {
		// The organisation's own app: it set the app up, so no prompt. The
		// grant puts it on their Connected apps page.
		granted = intersect(ar.Scopes, append(slices.Clone(client.RequiredScopes), client.OptionalScopes...))
		if slices.Contains(ar.Scopes, "openid") && !slices.Contains(granted, "openid") {
			granted = append([]string{"openid"}, granted...)
		}
		if err := a.store.SaveGrant(ctx, cur.user.ID, client.ID, granted); err != nil {
			return nil, http.StatusInternalServerError, "Something went wrong. Try again."
		}
	} else if g, err := a.store.Grant(ctx, cur.user.ID, client.ID); err == nil && !slices.Contains(ar.Prompt, "consent") &&
		len(intersect(required, g.Scopes)) == len(required) {
		granted = append([]string{"openid"}, append(required, intersect(optional, g.Scopes)...)...)
		granted = intersect(ar.Scopes, granted)
	}
	if granted != nil {
		if err := a.store.CompleteAuthRequest(ctx, ar.ID, cur.session, granted); err != nil {
			return nil, http.StatusInternalServerError, "Something went wrong. Try again."
		}
		a.logSignIn(r, store.SignIn{User: cur.user, Method: store.SignInApp, ClientID: client.ID, Success: true})
		res.Step, res.Redirect = "redirect", a.callbackURL(ar.ID)
		if ar.ResponseType == "saml" {
			res.Redirect = a.cfg.Issuer + "/saml/callback?id=" + url.QueryEscape(ar.ID)
		}
		return res, 0, ""
	}

	if promptNone {
		res.Step, res.Redirect = "redirect", a.denyURL(ar.ID, "consent_required")
		return res, 0, ""
	}
	res.Step = "consent"
	res.Scopes = &struct {
		Required []ScopeInfo `json:"required"`
		Optional []ScopeInfo `json:"optional"`
	}{describe(required), describe(optional)}
	return res, 0, ""
}

func withoutOpenID(s []string) []string {
	return slices.DeleteFunc(slices.Clone(s), func(x string) bool { return x == "openid" })
}

// callbackURL hands the finished request back to zitadel/oidc, which sends
// the code to the app.
func (a *API) callbackURL(id string) string {
	return a.cfg.Issuer + "/authorize/callback?id=" + url.QueryEscape(id)
}

// denyURL sends an OAuth error (access_denied, login_required…) to the app.
func (a *API) denyURL(id, reason string) string {
	return a.cfg.Issuer + "/authorize/deny?id=" + url.QueryEscape(id) + "&error=" + url.QueryEscape(reason)
}

func (a *API) respondNext(w http.ResponseWriter, r *http.Request, cur *current, authRequestID string) {
	res, status, msg := a.next(r, cur, authRequestID)
	if res == nil {
		writeError(w, status, "flow_error", msg)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// GET /api/flow?authRequestID=…: what the web UI should show now.
func (a *API) flow(w http.ResponseWriter, r *http.Request) {
	a.respondNext(w, r, a.current(r), r.URL.Query().Get("authRequestID"))
}

// POST /api/sign-in
func (a *API) signIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email         string `json:"email"`
		Password      string `json:"password"`
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	if body.Email == "" {
		writeFieldError(w, "email", "Enter your email address")
		return
	}
	if body.Password == "" {
		writeFieldError(w, "password", "Enter your password")
		return
	}
	ctx := r.Context()
	user, err := a.store.UserByEmail(ctx, body.Email)
	if err != nil {
		if !isNotFound(err) {
			serverError(w, r, err)
			return
		}
		secret.DummyCheck(body.Password)
		a.logSignIn(r, store.SignIn{Email: body.Email, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonUnknownUser})
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		a.logSignIn(r, store.SignIn{User: user, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonLocked})
		writeError(w, http.StatusTooManyRequests, "locked",
			"Too many attempts. Wait 15 minutes, or reset your password.")
		return
	}
	// Support accounts have no password: they're only opened by Keston staff
	// from their own account (see SupportSignIn).
	if user.IsSupport() {
		secret.DummyCheck(body.Password)
		a.logSignIn(r, store.SignIn{User: user, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonSupportAccount})
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	ok, err := secret.CheckPassword(user.PasswordHash, body.Password)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// Right password, but their organisation isn't verified yet: say so
	// (only to someone who proved who they are).
	if ok && user.Status == "active" && !user.OrganisationVerified {
		a.logSignIn(r, store.SignIn{User: user, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonUnverifiedOrg})
		writeUnverified(w)
		return
	}
	if !ok || !user.Usable() {
		_ = a.store.RecordLogin(ctx, user.ID, false)
		why := store.ReasonWrongPassword
		if ok {
			why = failReason(user)
		}
		a.logSignIn(r, store.SignIn{User: user, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
			Reason: why})
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	_ = a.store.RecordLogin(ctx, user.ID, true)
	a.logSignIn(r, store.SignIn{User: user, Method: store.SignInPassword, AuthRequestID: body.AuthRequestID,
		Success: true})

	// Without MFA: straight to required actions, if any (next() settles
	// the stage, and runs signedInFully once there are none). With MFA (an
	// authenticator app or a passkey), that comes first.
	stage := store.StageActions
	hasMFA, err := a.store.HasMFA(ctx, user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if hasMFA {
		stage = store.StagePassword
	}
	token, sess, err := a.store.CreateSession(ctx, user.ID, stage, []string{"pwd"}, r.UserAgent(), clientip.From(r),
		a.cfg.SessionTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// Added to this browser's signed-in accounts, as the active one.
	a.addSession(w, r, token, user.ID)
	if body.AuthRequestID != "" {
		_ = a.store.ChooseAccount(ctx, body.AuthRequestID)
	}
	a.respondNext(w, r, &current{session: sess, user: user, token: token}, body.AuthRequestID)
}

// POST /api/mfa: a code from an authenticator app, or a backup code.
func (a *API) mfa(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code          string `json:"code"`
		Kind          string `json:"kind"` // "app" (default) or "backup"
		AuthRequestID string `json:"authRequestID"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := a.current(r)
	if cur == nil || cur.session.Stage != store.StagePassword {
		writeError(w, http.StatusUnauthorized, "signed_out", "Sign in again to continue.")
		return
	}
	ctx := r.Context()
	logMethod := store.SignInMFA
	if body.Kind == "backup" {
		logMethod = store.SignInBackupCode
	}
	if cur.user.LockedUntil != nil && cur.user.LockedUntil.After(time.Now()) {
		a.logSignIn(r, store.SignIn{User: cur.user, Method: logMethod, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonLocked})
		writeError(w, http.StatusTooManyRequests, "locked", "Too many attempts. Wait 15 minutes and try again.")
		return
	}
	code := strings.ReplaceAll(strings.TrimSpace(body.Code), " ", "")
	ok := false
	method := "otp"
	if body.Kind == "backup" {
		method = "backup"
		used, err := a.store.UseBackupCode(ctx, cur.user.ID, secret.Hash(normaliseBackup(code)))
		if err != nil {
			serverError(w, r, err)
			return
		}
		ok = used
	} else if cur.user.TOTPEnabled && cur.user.TOTPSecret != nil {
		key, err := a.store.Box.Open(cur.user.TOTPSecret)
		if err != nil {
			serverError(w, r, err)
			return
		}
		ok = totp.Validate(code, string(key))
	}
	if !ok {
		_ = a.store.RecordLogin(ctx, cur.user.ID, false)
		a.logSignIn(r, store.SignIn{User: cur.user, Method: logMethod, AuthRequestID: body.AuthRequestID,
			Reason: store.ReasonMFAFailed})
		field := "code"
		msg := "That code didn't work. Check it and try again."
		if body.Kind == "backup" {
			msg = "That backup code didn't work, or has been used."
		}
		writeFieldError(w, field, msg)
		return
	}
	_ = a.store.RecordLogin(ctx, cur.user.ID, true)
	a.logSignIn(r, store.SignIn{User: cur.user, Method: logMethod, AuthRequestID: body.AuthRequestID, Success: true})
	sess, err := a.store.VerifySession(ctx, cur.session.ID, method)
	if err != nil {
		serverError(w, r, err)
		return
	}
	cur.session = sess
	a.respondNext(w, r, cur, body.AuthRequestID)
}

func normaliseBackup(code string) string {
	return strings.ToLower(strings.ReplaceAll(code, "-", ""))
}

// POST /api/consent: Allow, with the optional scopes left ticked.
func (a *API) consent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AuthRequestID string   `json:"authRequestID"`
		Scopes        []string `json:"scopes"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := a.current(r)
	if cur == nil || cur.session.Stage != store.StageVerified {
		writeError(w, http.StatusUnauthorized, "signed_out", "Sign in again to continue.")
		return
	}
	ctx := r.Context()
	ar, err := a.store.AuthRequestByID(ctx, body.AuthRequestID)
	if err != nil || ar.Done {
		writeError(w, http.StatusGone, "flow_error", "This sign-in link has expired. Go back to the app and try again.")
		return
	}
	client, err := a.store.ClientByID(ctx, ar.ClientID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	// What the app asked for and must have, plus the optional ones still ticked.
	granted := intersect(ar.Scopes, client.RequiredScopes)
	granted = append(granted, intersect(intersect(ar.Scopes, client.OptionalScopes), body.Scopes)...)
	if slices.Contains(ar.Scopes, "openid") && !slices.Contains(granted, "openid") {
		granted = append([]string{"openid"}, granted...)
	}
	if err := a.store.SaveGrant(ctx, cur.user.ID, client.ID, granted); err != nil {
		serverError(w, r, err)
		return
	}
	if err := a.store.CompleteAuthRequest(ctx, ar.ID, cur.session, granted); err != nil {
		serverError(w, r, err)
		return
	}
	a.logSignIn(r, store.SignIn{User: cur.user, Method: store.SignInApp, ClientID: client.ID, Success: true})
	writeJSON(w, http.StatusOK, flowResponse{Step: "redirect", Redirect: a.callbackURL(ar.ID)})
}

var _ = store.ErrNotFound

// rulesFor: the organisation's password rules, when a new password is among the actions.
func (a *API) rulesFor(ctx context.Context, cur *current, actions []string) []policy.Rule {
	if !slices.Contains(actions, ActionPassword) {
		return nil
	}
	return a.store.PolicyFor(ctx, cur.user.OrganisationID).Rules()
}

// graceFor: when MFA is among the actions and can still be put off, until when.
func (a *API) graceFor(ctx context.Context, cur *current, actions []string) *time.Time {
	if !slices.Contains(actions, ActionMFA) {
		return nil
	}
	return a.mfaGraceUntil(ctx, cur)
}
