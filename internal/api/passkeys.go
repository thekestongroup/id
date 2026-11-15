package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// Passkeys and security keys (WebAuthn). Three ceremonies:
//   - adding one, from the account's Security page (needs a recent sign-in);
//   - the MFA step after a password, instead of an authenticator code;
//   - signing in without a password, with a passkey (a discoverable
//     credential), from the sign-in page or the browser's autofill.
//
// Each ceremony's challenge is kept on the server (webauthn_ceremonies),
// and the browser gets a token for it to send back with its answer.

const (
	ceremonyTTL = 5 * time.Minute
	// Adding a passkey needs a sign-in this recent, or the password again.
	recentSignIn   = 10 * time.Minute
	maxPasskeyName = 64
)

// newWebAuthn: the relying party is the issuer's host (id.keston.localhost
// locally, id.keston.co live), and only the issuer's origin may use it.
func newWebAuthn(issuer string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:                  u.Hostname(),
		RPDisplayName:         "Keston ID",
		RPOrigins:             []string{u.Scheme + "://" + u.Host},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL},
		},
	})
}

func (a *API) passkeyRoutes(r chi.Router) {
	r.Post("/sign-in/passkey/options", a.passkeySignInOptions)
	r.Post("/sign-in/passkey", a.passkeySignIn)
	r.Post("/mfa/passkey/options", a.passkeyMFAOptions)
	r.Post("/mfa/passkey", a.passkeyMFA)
}

func (a *API) passkeyAccountRoutes(r chi.Router) {
	r.Get("/passkeys", a.listPasskeys)
	r.Post("/passkeys/options", a.passkeyRegisterOptions)
	r.Post("/passkeys", a.addPasskey)
	r.Patch("/passkeys/{passkeyID}", a.renamePasskey)
	r.Delete("/passkeys/{passkeyID}", a.removePasskey)
}

// waUser is a Keston account as go-webauthn sees it. Its user handle is the
// account's ID (16 bytes), so a passkey finds its account without an email.
type waUser struct {
	u     *store.User
	keys  []store.Passkey
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte                         { return userHandle(w.u.ID) }
func (w *waUser) WebAuthnName() string                       { return w.u.Email }
func (w *waUser) WebAuthnDisplayName() string                { return w.u.Name }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// passkey is the stored passkey for a credential the authenticator used.
func (w *waUser) passkey(id []byte) *store.Passkey {
	for i := range w.keys {
		if bytes.Equal(w.keys[i].Credential.ID, id) {
			return &w.keys[i]
		}
	}
	return nil
}

func userHandle(id string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil {
		return []byte(id)
	}
	return b
}

func userIDFromHandle(h []byte) string {
	if len(h) != 16 {
		return ""
	}
	s := hex.EncodeToString(h)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func (a *API) loadWAUser(ctx context.Context, u *store.User) (*waUser, error) {
	keys, err := a.store.PasskeysForUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	w := &waUser{u: u, keys: keys}
	for _, k := range keys {
		w.creds = append(w.creds, k.Credential)
	}
	return w, nil
}

// ceremonyBody is the browser's answer: the ceremony's token and the
// PublicKeyCredential (as JSON, from credential.toJSON()).
type ceremonyBody struct {
	Ceremony      string          `json:"ceremony"`
	Credential    json.RawMessage `json:"credential"`
	Name          string          `json:"name"`
	AuthRequestID string          `json:"authRequestID"`
}

func (a *API) startCeremony(w http.ResponseWriter, r *http.Request, purpose, userID, sessionID string,
	data *webauthn.SessionData, options any) {
	token, err := a.store.StartCeremony(r.Context(), purpose, userID, sessionID, data, ceremonyTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ceremony": token, "options": options})
}

func ceremonyExpired(w http.ResponseWriter) {
	writeError(w, http.StatusGone, "expired", "That took too long. Try again.")
}

func passkeyFailed(w http.ResponseWriter, r *http.Request, err error) {
	slog.InfoContext(r.Context(), "passkey not accepted", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusUnauthorized, "passkey_failed", "That passkey didn't work. Try again, or use another way.")
}

// usedPasskey records a sign-in with a passkey. A sign count that went
// backwards suggests a copied authenticator, so it's refused.
func (a *API) usedPasskey(ctx context.Context, wu *waUser, cred *webauthn.Credential) error {
	if cred.Authenticator.CloneWarning {
		return errors.New("sign count went backwards: the authenticator may have been copied")
	}
	key := wu.passkey(cred.ID)
	if key == nil {
		return errors.New("passkey not found")
	}
	return a.store.PasskeyUsed(ctx, key.ID, cred)
}

// ── Signing in without a password ───────────────────────────────────────

// POST /api/sign-in/passkey/options: a challenge for any passkey on this
// site (the browser lets people choose one, or offers them in autofill).
func (a *API) passkeySignInOptions(w http.ResponseWriter, r *http.Request) {
	options, data, err := a.webauthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.startCeremony(w, r, store.CeremonySignIn, "", "", data, options.Response)
}

// POST /api/sign-in/passkey {ceremony, credential, authRequestID}: signs in
// fully. A passkey is something you have, unlocked by something you are or
// know, so it's MFA on its own.
func (a *API) passkeySignIn(w http.ResponseWriter, r *http.Request) {
	var body ceremonyBody
	if !decode(w, r, &body) {
		return
	}
	ctx := r.Context()
	data, err := a.store.TakeCeremony(ctx, body.Ceremony, store.CeremonySignIn, "", "")
	if isNotFound(err) {
		ceremonyExpired(w)
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		passkeyFailed(w, r, err)
		return
	}
	var found *waUser
	handler := func(rawID, handle []byte) (webauthn.User, error) {
		u, err := a.store.UserByID(ctx, userIDFromHandle(handle))
		if err != nil {
			return nil, err
		}
		if found, err = a.loadWAUser(ctx, u); err != nil {
			return nil, err
		}
		return found, nil
	}
	_, cred, err := a.webauthn.ValidatePasskeyLogin(handler, *data, parsed)
	if err != nil {
		passkeyFailed(w, r, err)
		return
	}
	user := found.u
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "locked",
			"Too many attempts. Wait 15 minutes, or reset your password.")
		return
	}
	if !user.Usable() || user.IsSupport() {
		passkeyFailed(w, r, errors.New("account can't sign in"))
		return
	}
	if err := a.usedPasskey(ctx, found, cred); err != nil {
		passkeyFailed(w, r, err)
		return
	}
	_ = a.store.RecordLogin(ctx, user.ID, true)
	token, sess, err := a.store.CreateSession(ctx, user.ID, "verified", []string{"hwk", "mfa"}, r.UserAgent(),
		clientIP(r), a.cfg.SessionTTL)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.signedInFully(ctx, user)
	a.addSession(w, r, token, user.ID)
	if body.AuthRequestID != "" {
		_ = a.store.ChooseAccount(ctx, body.AuthRequestID)
	}
	a.respondNext(w, r, &current{session: sess, user: user, token: token}, body.AuthRequestID)
}

// ── The MFA step ────────────────────────────────────────────────────────

// mfaAtStep: the session that's signed in with a password and is at its
// MFA step, or nil (having written the error).
func (a *API) mfaAtStep(w http.ResponseWriter, r *http.Request) *current {
	cur := a.current(r)
	if cur == nil || cur.session.Stage != "password" {
		writeError(w, http.StatusUnauthorized, "signed_out", "Sign in again to continue.")
		return nil
	}
	if cur.user.LockedUntil != nil && cur.user.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "locked", "Too many attempts. Wait 15 minutes and try again.")
		return nil
	}
	return cur
}

// POST /api/mfa/passkey/options: a challenge for one of this account's
// passkeys or security keys.
func (a *API) passkeyMFAOptions(w http.ResponseWriter, r *http.Request) {
	cur := a.mfaAtStep(w, r)
	if cur == nil {
		return
	}
	wu, err := a.loadWAUser(r.Context(), cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	if len(wu.creds) == 0 {
		writeError(w, http.StatusConflict, "no_passkeys", "You haven't added a passkey to your account.")
		return
	}
	options, data, err := a.webauthn.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.startCeremony(w, r, store.CeremonyMFA, cur.user.ID, cur.session.ID, data, options.Response)
}

// POST /api/mfa/passkey {ceremony, credential, authRequestID}
func (a *API) passkeyMFA(w http.ResponseWriter, r *http.Request) {
	var body ceremonyBody
	if !decode(w, r, &body) {
		return
	}
	cur := a.mfaAtStep(w, r)
	if cur == nil {
		return
	}
	ctx := r.Context()
	data, err := a.store.TakeCeremony(ctx, body.Ceremony, store.CeremonyMFA, cur.user.ID, cur.session.ID)
	if isNotFound(err) {
		ceremonyExpired(w)
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		passkeyFailed(w, r, err)
		return
	}
	wu, err := a.loadWAUser(ctx, cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	cred, err := a.webauthn.ValidateLogin(wu, *data, parsed)
	if err == nil {
		err = a.usedPasskey(ctx, wu, cred)
	}
	if err != nil {
		_ = a.store.RecordLogin(ctx, cur.user.ID, false)
		passkeyFailed(w, r, err)
		return
	}
	_ = a.store.RecordLogin(ctx, cur.user.ID, true)
	sess, err := a.store.VerifySession(ctx, cur.session.ID, "hwk")
	if err != nil {
		serverError(w, r, err)
		return
	}
	cur.session = sess
	a.signedInFully(ctx, cur.user)
	a.respondNext(w, r, cur, body.AuthRequestID)
}

// mfaMethods: what the MFA page offers someone.
type mfaMethods struct {
	App     bool `json:"app"`
	Passkey bool `json:"passkey"`
}

func (a *API) mfaMethodsFor(ctx context.Context, u *store.User) *mfaMethods {
	n, _ := a.store.PasskeyCount(ctx, u.ID)
	return &mfaMethods{App: u.TOTPEnabled, Passkey: n > 0}
}

// ── The account's passkeys ──────────────────────────────────────────────

type passkeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	// Synced between devices by a password manager (iCloud Keychain, Google
	// Password Manager…), rather than kept on one device or security key.
	Synced bool `json:"synced"`
}

func viewPasskey(p *store.Passkey) passkeyView {
	return passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt,
		Synced: p.Credential.Flags.BackupEligible}
}

// GET /v1/me/passkeys
func (a *API) listPasskeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.store.PasskeysForUser(r.Context(), from(r).user.ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]passkeyView, len(keys))
	for i := range keys {
		out[i] = viewPasskey(&keys[i])
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /v1/me/passkeys/options {password?}: starts adding a passkey. Needs
// a sign-in in the last 10 minutes, or the password again.
func (a *API) passkeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeOptional(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return
	}
	cur := from(r)
	// An access token without a session counts as not recent.
	if cur.session == nil || time.Since(cur.session.AuthTime) > recentSignIn {
		if body.Password == "" {
			writeError(w, http.StatusForbidden, "reauthenticate", "Enter your password to add a passkey.")
			return
		}
		ok, err := secret.CheckPassword(cur.user.PasswordHash, body.Password)
		if err != nil {
			serverError(w, r, err)
			return
		}
		if !ok {
			writeFieldError(w, "password", "That isn't your password")
			return
		}
	}
	wu, err := a.loadWAUser(r.Context(), cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	options, data, err := a.webauthn.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			// Passkeys sign in on their own; older security keys that can't
			// store one still work as MFA.
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.startCeremony(w, r, store.CeremonyRegister, cur.user.ID, "", data, options.Response)
}

func passkeyName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && utf8.RuneCountInString(s) <= maxPasskeyName
}

// POST /v1/me/passkeys {ceremony, credential, name}
func (a *API) addPasskey(w http.ResponseWriter, r *http.Request) {
	var body ceremonyBody
	if !decode(w, r, &body) {
		return
	}
	name, ok := passkeyName(body.Name)
	if !ok {
		writeFieldError(w, "name", "Enter a name of up to 64 characters")
		return
	}
	cur := from(r)
	ctx := r.Context()
	data, err := a.store.TakeCeremony(ctx, body.Ceremony, store.CeremonyRegister, cur.user.ID, "")
	if isNotFound(err) {
		ceremonyExpired(w)
		return
	} else if err != nil {
		serverError(w, r, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		passkeyFailed(w, r, err)
		return
	}
	wu, err := a.loadWAUser(ctx, cur.user)
	if err != nil {
		serverError(w, r, err)
		return
	}
	cred, err := a.webauthn.CreateCredential(wu, *data, parsed)
	if err != nil {
		passkeyFailed(w, r, err)
		return
	}
	key, err := a.store.AddPasskey(ctx, cur.user.ID, name, cred)
	if isUniqueViolation(err) {
		writeError(w, http.StatusConflict, "exists", "That passkey is already on an account.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.InfoContext(ctx, "passkey added", "user", cur.user.ID, "passkey", key.ID)
	writeJSON(w, http.StatusCreated, viewPasskey(key))
}

// PATCH /v1/me/passkeys/{id} {name}
func (a *API) renamePasskey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	name, ok := passkeyName(body.Name)
	if !ok {
		writeFieldError(w, "name", "Enter a name of up to 64 characters")
		return
	}
	key, err := a.store.RenamePasskey(r.Context(), from(r).user.ID, chi.URLParam(r, "passkeyID"), name)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "That passkey has been removed.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, viewPasskey(key))
}

// DELETE /v1/me/passkeys/{id}
func (a *API) removePasskey(w http.ResponseWriter, r *http.Request) {
	cur := from(r)
	err := a.store.DeletePasskey(r.Context(), cur.user.ID, chi.URLParam(r, "passkeyID"))
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "That passkey has already been removed.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.InfoContext(r.Context(), "passkey removed", "user", cur.user.ID, "passkey", chi.URLParam(r, "passkeyID"))
	w.WriteHeader(http.StatusNoContent)
}
