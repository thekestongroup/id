package api

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
	"rsc.io/qr"

	"github.com/thekestongroup/id/internal/secret"
)

const minPasswordLength = 12

// GET /api/me
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": viewUser(cur.user),
		"security": map[string]any{
			"twoStep":           cur.user.TOTPEnabled,
			"backupCodesLeft":   len(cur.user.BackupCodes),
			"passwordChangedAt": cur.user.PasswordChangedAt,
		},
	})
}

// GET /api/me/apps: apps with access, and what each can do.
func (a *API) apps(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	grants, err := a.store.GrantsForUser(r.Context(), cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	type appView struct {
		Client    clientView  `json:"client"`
		Scopes    []ScopeInfo `json:"scopes"`
		GrantedAt time.Time   `json:"grantedAt"`
	}
	out := []appView{}
	for _, g := range grants {
		c, err := a.store.ClientByID(r.Context(), g.ClientID)
		if err != nil {
			continue
		}
		redirect := ""
		if len(c.RedirectURIs) > 0 {
			redirect = c.RedirectURIs[0]
		}
		out = append(out, appView{Client: viewClient(c, redirect), Scopes: describe(g.Scopes), GrantedAt: g.GrantedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// DELETE /api/me/apps/{clientID}: remove an app's access.
func (a *API) revokeApp(w http.ResponseWriter, r *http.Request) {
	if err := a.store.RevokeClient(r.Context(), from(r).user.ID, chi.URLParam(r, "clientID")); err != nil {
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
func (a *API) endSession(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	id := chi.URLParam(r, "sessionID")
	list, err := a.store.SessionsForUser(r.Context(), cur.user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	for _, s := range list {
		if s.ID == id {
			if err := a.store.DeleteSession(r.Context(), id); err != nil {
				serverError(w, r, err)
				return
			}
			if id == cur.session.ID {
				a.clearSessionCookie(w)
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
	if utf8.RuneCountInString(body.New) < minPasswordLength {
		writeFieldError(w, "new", "Use at least 12 characters")
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
	if err := a.store.DeleteOtherSessions(ctx, cur.user.ID, cur.session.ID); err != nil {
		serverError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/me/two-step/setup: a new authenticator secret, not yet on.
func (a *API) twoStepSetup(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	// A new secret would replace the one in use: turn it off first.
	if cur.user.TOTPEnabled {
		writeError(w, http.StatusConflict, "already_on", "Two-step verification is already on.")
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

// POST /api/me/two-step/enable: confirm with a code, get backup codes.
func (a *API) twoStepEnable(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusConflict, "no_setup", "Start setting up two-step verification first.")
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

// POST /api/me/two-step/disable: needs the password.
func (a *API) twoStepDisable(w http.ResponseWriter, r *http.Request) {
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
