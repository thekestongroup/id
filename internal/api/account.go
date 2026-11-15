package api

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"rsc.io/qr"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// GET /api/me
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	org, err := a.store.OrganisationByID(r.Context(), cur.user.OrganisationID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	passkeys, err := a.store.PasskeyCount(r.Context(), cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":     a.viewUser(cur.user),
		"username": username(cur.user.Email),
		"domain":   org.Domain,
		// What this person may change themselves (their organisation decides).
		"editable": org.ProfileEditing,
		"security": map[string]any{
			// MFA is on with an authenticator app or any passkey.
			"mfa":               cur.user.TOTPEnabled || passkeys > 0,
			"authenticatorApp":  cur.user.TOTPEnabled,
			"passkeys":          passkeys,
			"backupCodesLeft":   len(cur.user.BackupCodes),
			"passwordChangedAt": cur.user.PasswordChangedAt,
			"passwordRules":     a.store.PolicyFor(r.Context(), cur.user.OrganisationID).Rules(),
		},
	})
}

// GET /api/me/apps: the apps on this account, from what the organisation
// sets (Keston Admin → Apps, by default and per group):
//   - "forced": on, and can't be removed ("Enabled by your organisation")
//   - "enabled": on, and can be removed ("Added by your organisation")
//   - "user": apps this person signed in to themselves (can be removed)
//
// Disabled apps aren't shown.
func (a *API) apps(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	ctx := r.Context()
	eff, err := a.store.EffectiveApps(ctx, cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	grants, err := a.store.GrantsForUser(ctx, cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	removed, err := a.store.RemovedApps(ctx, cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	granted := map[string]store.Grant{}
	for _, g := range grants {
		granted[g.ClientID] = g
	}
	type appView struct {
		Client    clientView  `json:"client"`
		Source    string      `json:"source"` // forced, enabled, user
		Removable bool        `json:"removable"`
		Scopes    []ScopeInfo `json:"scopes"`
		// When this person allowed it (nil: never signed in to it yet).
		GrantedAt *time.Time `json:"grantedAt,omitempty"`
	}
	all, err := a.store.AllClients(ctx)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := []appView{}
	for i := range all {
		c := &all[i]
		mode, set := eff[c.ID]
		_, signedIn := granted[c.ID]
		source := "user"
		switch {
		case set && mode == store.AppDisabled:
			continue
		case set && mode == store.AppForced:
			source = "forced"
		case set && mode == store.AppEnabled && !removed[c.ID]:
			source = "enabled"
		case !signedIn:
			continue
		}
		v := appView{Client: viewClient(c, first(c.RedirectURIs)), Source: source, Removable: source != "forced",
			Scopes: []ScopeInfo{}}
		if g, ok := granted[c.ID]; ok {
			v.Scopes = describe(g.Scopes)
			t := g.GrantedAt
			v.GrantedAt = &t
		}
		out = append(out, v)
	}
	// The organisation's apps first, then the person's own.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source != "user" && out[j].Source == "user" })
	writeJSON(w, http.StatusOK, out)
}

func first(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// DELETE /api/me/apps/{clientID}: remove an app. Apps the organisation has
// forced can't be removed.
func (a *API) revokeApp(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	ctx := r.Context()
	id := chi.URLParam(r, "clientID")
	eff, err := a.store.EffectiveApps(ctx, cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	switch eff[id] {
	case store.AppForced:
		writeError(w, http.StatusForbidden, "required", "Your organisation has made this app always on for your account, so it can’t be removed.")
		return
	case store.AppEnabled:
		// Hidden for this person from now on, and its access revoked.
		err = a.store.RemoveAppForUser(ctx, cur.user.ID, id)
	default:
		err = a.store.RevokeClient(ctx, cur.user.ID, id)
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/me/sessions: where this account is signed in.
func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	list, err := a.store.SessionsForUser(r.Context(), cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	type sessionView struct {
		ID         string    `json:"id"`
		UserAgent  string    `json:"userAgent"`
		IP         string    `json:"ip"`
		CreatedAt  time.Time `json:"createdAt"`
		LastSeenAt time.Time `json:"lastSeenAt"`
		Current    bool      `json:"current"`
	}
	out := make([]sessionView, 0, len(list))
	for _, s := range list {
		out = append(out, sessionView{ID: s.ID, UserAgent: s.UserAgent, IP: s.IP, CreatedAt: s.CreatedAt,
			LastSeenAt: s.LastSeenAt, Current: s.ID == cur.session.ID})
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /api/me/sessions/{sessionID}: sign out another device.
func (a *API) signOutDevice(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	id := chi.URLParam(r, "sessionID")
	list, err := a.store.SessionsForUser(r.Context(), cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	for _, s := range list {
		if s.ID == id {
			// Signs that device out of Keston ID and of the apps it signed in to.
			if id == cur.session.ID {
				a.EndBrowserSession(w, r)
			} else {
				a.end(r.Context(), id)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "That session has already ended.")
}

// POST /api/me/password. Signs out every other device.
func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := from(r)
	ok, err := secret.CheckPassword(cur.user.PasswordHash, body.Current)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		writeFieldError(w, "current", "That isn't your current password")
		return
	}
	// The organisation's rules (on top of the baseline). The username can't
	// be the password either.
	pol := a.store.PolicyFor(r.Context(), cur.user.OrganisationID)
	if failed := pol.Check(body.New, username(cur.user.Email)); len(failed) > 0 {
		writeFieldError(w, "new", policy.Message(failed))
		return
	}
	if body.New == body.Current {
		writeFieldError(w, "new", "Choose a password you haven't used here")
		return
	}
	ctx := r.Context()
	if err := a.store.SetPassword(ctx, cur.user.ID, secret.HashPassword(body.New)); err != nil {
		serverError(w, r, err)
		return
	}
	// Every other device is signed out, of Keston ID and its apps.
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
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/me/mfa/setup: a new authenticator secret, not yet on.
func (a *API) mfaSetup(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	// A new secret would replace the one in use: turn it off first.
	if cur.user.TOTPEnabled {
		writeError(w, http.StatusConflict, "already_on", "MFA is already on.")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Keston ID", AccountName: cur.user.Email})
	if err != nil {
		serverError(w, r, err)
		return
	}
	if err := a.store.SetTOTP(r.Context(), cur.user.ID, a.store.Box.Seal([]byte(key.Secret()))); err != nil {
		serverError(w, r, err)
		return
	}
	// The QR code people scan with their authenticator app, as a PNG data URI.
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

// POST /api/me/mfa/enable: confirm with a code, get backup codes.
func (a *API) mfaEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	ctx := r.Context()
	user, err := a.store.UserByID(ctx, from(r).user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if user.TOTPSecret == nil {
		writeError(w, http.StatusConflict, "no_setup", "Start setting up MFA first.")
		return
	}
	key, err := a.store.Box.Open(user.TOTPSecret)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !totp.Validate(strings.ReplaceAll(body.Code, " ", ""), string(key)) {
		writeFieldError(w, "code", "That code didn't work. Check the time on your phone and try again.")
		return
	}
	codes, hashes := backupCodes(10)
	if err := a.store.EnableTOTP(ctx, user.ID, hashes); err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backupCodes": codes})
}

// POST /api/me/mfa/disable: needs the password.
func (a *API) mfaDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := from(r)
	ok, err := secret.CheckPassword(cur.user.PasswordHash, body.Password)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !ok {
		writeFieldError(w, "password", "That isn't your password")
		return
	}
	if err := a.store.DisableTOTP(r.Context(), cur.user.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// backupCodes makes one-time codes like "k7q2-m9xd", returning them and
// their hashes (only the hashes are kept).
func backupCodes(n int) ([]string, []string) {
	enc := base32.NewEncoding("abcdefghjkmnpqrstuvwxyz123456789").WithPadding(base32.NoPadding)
	codes, hashes := make([]string, n), make([]string, n)
	for i := range n {
		b := make([]byte, 5)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		raw := enc.EncodeToString(b)[:8]
		codes[i] = raw[:4] + "-" + raw[4:]
		hashes[i] = secret.Hash(raw)
	}
	return codes, hashes
}

// username is the part of an email before the @.
func username(email string) string {
	name, _, _ := strings.Cut(email, "@")
	return name
}

// PATCH /api/me {name?, username?}: only the fields the organisation allows.
func (a *API) updateProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     *string `json:"name"`
		Username *string `json:"username"`
	}
	if !decode(w, r, &body) {
		return
	}
	cur := from(r)
	ctx := r.Context()
	org, err := a.store.OrganisationByID(ctx, cur.user.OrganisationID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	var name, email *string
	if body.Name != nil {
		if !org.ProfileEditing.Name {
			writeFieldError(w, "name", "Your organisation has restricted changing your name.")
			return
		}
		if !profile.ValidName(*body.Name) {
			writeFieldError(w, "name", "Enter your name")
			return
		}
		n := strings.TrimSpace(*body.Name)
		name = &n
	}
	if body.Username != nil {
		if !org.ProfileEditing.Email {
			writeFieldError(w, "username", "Your organisation has restricted changing your email.")
			return
		}
		u := profile.NormaliseUsername(*body.Username)
		if !profile.ValidUsername(u) {
			writeFieldError(w, "username", profile.UsernameHelp)
			return
		}
		e := u + "@" + org.Domain
		email = &e
	}
	user, err := a.store.UpdateProfile(ctx, cur.user.ID, name, email)
	if isUniqueViolation(err) {
		writeFieldError(w, "username", "Someone else already has that email.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.viewUser(user))
}

// PUT /api/me/picture (the image as the body): if the organisation allows.
func (a *API) setPicture(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	org, err := a.store.OrganisationByID(r.Context(), cur.user.OrganisationID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !org.ProfileEditing.Picture {
		writeError(w, http.StatusForbidden, "restricted", "Your organisation has restricted changing your picture.")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, profile.MaxPictureBytes+1))
	if err != nil && !errors.As(err, new(*http.MaxBytesError)) {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the picture.")
		return
	}
	contentType, err := profile.CheckPicture(data)
	if err != nil {
		writeFieldError(w, "picture", err.Error())
		return
	}
	if err := a.store.SetPicture(r.Context(), cur.user.ID, data, contentType); err != nil {
		serverError(w, r, err)
		return
	}
	user, _ := a.store.UserByID(r.Context(), cur.user.ID)
	writeJSON(w, http.StatusOK, a.viewUser(user))
}

func (a *API) removePicture(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	org, err := a.store.OrganisationByID(r.Context(), cur.user.OrganisationID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if !org.ProfileEditing.Picture {
		writeError(w, http.StatusForbidden, "restricted", "Your organisation has restricted changing your picture.")
		return
	}
	if err := a.store.SetPicture(r.Context(), cur.user.ID, nil, ""); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
