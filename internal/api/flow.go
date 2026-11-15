package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// flowResponse tells the web UI which page comes next.
//
//	step: "sign-in" | "choose" | "mfa" | "consent" | "redirect" | "account"
type flowResponse struct {
	Step     string      `json:"step"`
	Redirect string      `json:"redirect,omitempty"`
	Client   *clientView `json:"client,omitempty"`
	Scopes   *struct {
		Required []ScopeInfo `json:"required"`
		Optional []ScopeInfo `json:"optional"`
	} `json:"scopes,omitempty"`
	User *userView `json:"user,omitempty"`
}

// next works out where someone goes from here: the heart of the sign-in flow.
// Without an auth request (signing in to Keston ID itself), it ends at the
// account page; with one, at the app.
func (a *API) next(r *http.Request, cur *current, authRequestID string) (*flowResponse, int, string) {
	ctx := r.Context()
	res := &flowResponse{}
	if cur != nil {
		u := a.viewUser(cur.user)
		res.User = &u
	}

	if authRequestID == "" {
		switch {
		case cur == nil:
			res.Step = "sign-in"
		case cur.session.Stage == "password":
			res.Step = "mfa"
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
	if err != nil {
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
	if cur.session.Stage == "password" {
		res.Step = "mfa"
		return res, 0, ""
	}
	// Another organisation's own app: only its users can sign in to it.
	if client.OrganisationID != nil && *client.OrganisationID != cur.user.OrganisationID {
		return nil, http.StatusForbidden, client.Name + " is only for another organisation's accounts. " +
			"Sign in with your account there, or ask the app's admins."
	}
	// Turned off for them by their organisation (Keston Admin → Apps).
	if eff, err := a.store.EffectiveApps(ctx, cur.user); err == nil && eff[client.ID] == store.AppDisabled {
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
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "locked",
			"Too many attempts. Wait 15 minutes, or reset your password.")
		return
	}
	// Support accounts have no password: they're only opened by Keston staff
	// from their own account (see SupportSignIn).
	if user.IsSupport() {
		secret.DummyCheck(body.Password)
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	ok, err := secret.CheckPassword(user.PasswordHash, body.Password)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok || !user.Usable() {
		_ = a.store.RecordLogin(ctx, user.ID, false)
		writeFieldError(w, "password", "Incorrect email or password")
		return
	}
	_ = a.store.RecordLogin(ctx, user.ID, true)

	stage := "verified"
	if user.TOTPEnabled {
		stage = "password"
	}
	token, sess, err := a.store.CreateSession(ctx, user.ID, stage, []string{"pwd"}, r.UserAgent(), clientIP(r),
		a.cfg.SessionTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if stage == "verified" {
		a.signedInFully(ctx, user)
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
	if cur == nil || cur.session.Stage != "password" {
		writeError(w, http.StatusUnauthorized, "signed_out", "Sign in again to continue.")
		return
	}
	ctx := r.Context()
	if cur.user.LockedUntil != nil && cur.user.LockedUntil.After(time.Now()) {
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
	} else if cur.user.TOTPSecret != nil {
		key, err := a.store.Box.Open(cur.user.TOTPSecret)
		if err != nil {
			serverError(w, r, err)
			return
		}
		ok = totp.Validate(code, string(key))
	}
	if !ok {
		_ = a.store.RecordLogin(ctx, cur.user.ID, false)
		field := "code"
		msg := "That code didn't work. Check it and try again."
		if body.Kind == "backup" {
			msg = "That backup code didn't work, or has been used."
		}
		writeFieldError(w, field, msg)
		return
	}
	_ = a.store.RecordLogin(ctx, cur.user.ID, true)
	sess, err := a.store.VerifySession(ctx, cur.session.ID, method)
	if err != nil {
		serverError(w, r, err)
		return
	}
	cur.session = sess
	a.signedInFully(ctx, cur.user)
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
	if cur == nil || cur.session.Stage != "verified" {
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
	writeJSON(w, http.StatusOK, flowResponse{Step: "redirect", Redirect: a.callbackURL(ar.ID)})
}

var _ = store.ErrNotFound
