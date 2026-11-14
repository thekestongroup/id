// Package adminapi is the API behind Keston Admin (admin.keston.co):
// organisations, their accounts and their password policies.
//
// Every request carries a Keston ID access token issued to the "admin"
// client (Authorization: Bearer …). Who can do what:
//   - platform admins (The Keston Group's staff): every organisation, and
//     creating new ones
//   - global admins: their own organisation only
//   - everyone else: nothing
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// ClientID is Keston Admin's OAuth client: only its tokens are accepted.
const ClientID = "admin"

// VerifyToken checks an access token's signature, issuer and expiry.
type VerifyToken func(ctx context.Context, token string) (*oidc.AccessTokenClaims, error)

type API struct {
	store  *store.Store
	verify VerifyToken
}

func New(s *store.Store, verify VerifyToken) *API { return &API{store: s, verify: verify} }

func (a *API) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore, a.authenticate)

	r.Get("/me", a.me)
	r.Get("/password-rules", a.baselineRules)
	r.Post("/password-check", a.passwordCheck)
	r.Get("/domains/{domain}", a.domainAvailable)

	r.Get("/organisations", a.listOrganisations)
	r.Post("/organisations", a.createOrganisation)
	r.Route("/organisations/{orgID}", func(r chi.Router) {
		r.Use(a.requireOrganisation)
		r.Get("/", a.getOrganisation)
		r.Get("/users", a.listUsers)
		r.Post("/users", a.createUser)
		r.Post("/users/{userID}/reset-password", a.resetPassword)
		r.Post("/users/{userID}/status", a.setStatus)
		r.Get("/password-policy", a.getPolicy)
		r.Put("/password-policy", a.putPolicy)
	})
	return r
}

// ── Auth ─────────────────────────────────────────────────────────────────

type ctxKey int

const (
	userKey ctxKey = iota
	orgKey
)

func caller(r *http.Request) *store.User { return r.Context().Value(userKey).(*store.User) }
func organisation(r *http.Request) *store.Organisation {
	return r.Context().Value(orgKey).(*store.Organisation)
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token == "" {
			writeError(w, http.StatusUnauthorized, "signed_out", "Sign in to continue.")
			return
		}
		claims, err := a.verify(r.Context(), token)
		if err != nil || claims.ClientID != ClientID {
			writeError(w, http.StatusUnauthorized, "signed_out", "Your session has ended. Sign in again.")
			return
		}
		// Still valid: not revoked (signed out, access removed, disabled).
		if _, userID, _, err := a.store.AccessTokenActive(r.Context(), claims.JWTID); err != nil || userID == nil ||
			*userID != claims.Subject {
			writeError(w, http.StatusUnauthorized, "signed_out", "Your session has ended. Sign in again.")
			return
		}
		user, err := a.store.UserByID(r.Context(), claims.Subject)
		if err != nil || user.Status != "active" {
			writeError(w, http.StatusUnauthorized, "signed_out", "Your session has ended. Sign in again.")
			return
		}
		if !user.PlatformAdmin && user.Role != "global_admin" {
			writeError(w, http.StatusForbidden, "not_admin",
				"Keston Admin is for your organisation's global admins. Ask one of them if you need something changed.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	})
}

// canManage: platform admins manage every organisation; global admins
// their own.
func canManage(u *store.User, orgID string) bool {
	return u.PlatformAdmin || (u.Role == "global_admin" && u.OrganisationID == orgID)
}

func (a *API) requireOrganisation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "orgID")
		if !canManage(caller(r), id) {
			writeError(w, http.StatusNotFound, "not_found", "That organisation doesn't exist.")
			return
		}
		org, err := a.store.OrganisationByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "That organisation doesn't exist.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orgKey, org)))
	})
}

// ── Validation ───────────────────────────────────────────────────────────

var (
	domainRE   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	usernameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
)

func normaliseDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
	d = strings.TrimPrefix(d, "@")
	return strings.TrimSuffix(d, "/")
}

func validDomain(d string) bool { return len(d) <= 253 && domainRE.MatchString(d) }

func normaliseUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

const domainHelp = "Enter a domain like greenfield.sch.uk, without https:// or www."
const usernameHelp = "Use lowercase letters, numbers, dots, dashes or underscores, like j.smith"

// ── Handlers: you and the rules ──────────────────────────────────────────

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	org, _ := a.store.OrganisationByID(r.Context(), u.OrganisationID)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          userView(u),
		"platformAdmin": u.PlatformAdmin,
		"organisation":  org,
	})
}

// The baseline rules, for a new organisation (which has no rules of its own yet).
func (a *API) baselineRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, policy.Policy{}.Rules())
}

type ruleResult struct {
	policy.Rule
	Met bool `json:"met"`
}

// POST /password-check: which rules a password meets, for the live
// checklist. Against an organisation's policy, or the baseline.
func (a *API) passwordCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrganisationID string `json:"organisationId"`
		Password       string `json:"password"`
		Username       string `json:"username"`
	}
	if !decode(w, r, &body) {
		return
	}
	pol := policy.Policy{}
	if body.OrganisationID != "" {
		if !canManage(caller(r), body.OrganisationID) {
			writeError(w, http.StatusNotFound, "not_found", "That organisation doesn't exist.")
			return
		}
		pol = a.store.PolicyFor(r.Context(), body.OrganisationID)
	}
	failed := map[string]bool{}
	for _, f := range pol.Check(body.Password, normaliseUsername(body.Username)) {
		failed[f.ID] = true
	}
	out := []ruleResult{}
	for _, rule := range pol.Rules() {
		out = append(out, ruleResult{Rule: rule, Met: body.Password != "" && !failed[rule.ID]})
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /domains/{domain}: is it valid and free?
func (a *API) domainAvailable(w http.ResponseWriter, r *http.Request) {
	d := normaliseDomain(chi.URLParam(r, "domain"))
	res := map[string]any{"domain": d, "valid": validDomain(d), "available": false}
	if !validDomain(d) {
		res["message"] = domainHelp
		writeJSON(w, http.StatusOK, res)
		return
	}
	taken, err := a.store.DomainTaken(r.Context(), d)
	if err != nil {
		serverError(w, r, err)
		return
	}
	res["available"] = !taken
	if taken {
		res["message"] = d + " already belongs to another organisation."
	}
	writeJSON(w, http.StatusOK, res)
}

// ── Organisations ────────────────────────────────────────────────────────

func (a *API) listOrganisations(w http.ResponseWriter, r *http.Request) {
	u := caller(r)
	if !u.PlatformAdmin {
		org, err := a.store.OrganisationByID(r.Context(), u.OrganisationID)
		if err != nil {
			serverError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, []store.Organisation{*org})
		return
	}
	orgs, err := a.store.Organisations(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

// POST /organisations: platform admins only. The organisation and its first
// global admin (username@domain), together.
func (a *API) createOrganisation(w http.ResponseWriter, r *http.Request) {
	if !caller(r).PlatformAdmin {
		writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can create organisations.")
		return
	}
	var body struct {
		Name          string `json:"name"`
		Domain        string `json:"domain"`
		AdminName     string `json:"adminName"`
		AdminUsername string `json:"adminUsername"`
		AdminPassword string `json:"adminPassword"`
	}
	if !decode(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	domain := normaliseDomain(body.Domain)
	user := normaliseUsername(body.AdminUsername)
	adminName := strings.TrimSpace(body.AdminName)
	switch {
	case name == "" || len(name) > 200:
		writeFieldError(w, "name", "Enter the organisation's name")
		return
	case !validDomain(domain):
		writeFieldError(w, "domain", domainHelp)
		return
	case adminName == "" || len(adminName) > 200:
		writeFieldError(w, "adminName", "Enter the global admin's name")
		return
	case !usernameRE.MatchString(user):
		writeFieldError(w, "adminUsername", usernameHelp)
		return
	}
	if failed := (policy.Policy{}).Check(body.AdminPassword, user, name); len(failed) > 0 {
		writeFieldError(w, "adminPassword", policy.Message(failed))
		return
	}
	org, admin, err := a.store.CreateOrganisation(r.Context(), name, domain, store.NewUser{
		Email:        user + "@" + domain,
		Name:         adminName,
		PasswordHash: secret.HashPassword(body.AdminPassword),
	})
	if isUniqueViolation(err) {
		writeFieldError(w, "domain", domain+" already belongs to another organisation.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("organisation created", "organisation", org.ID, "domain", domain, "by", caller(r).ID)
	writeJSON(w, http.StatusCreated, map[string]any{"organisation": org, "admin": userView(admin)})
}

func (a *API) getOrganisation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, organisation(r))
}

// ── Accounts ─────────────────────────────────────────────────────────────

type userJSON struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	PlatformAdmin bool   `json:"platformAdmin"`
	Status        string `json:"status"`
	TwoStep       bool   `json:"twoStep"`
	Locked        bool   `json:"locked"`
	CreatedAt     string `json:"createdAt"`
	PasswordSetAt string `json:"passwordChangedAt"`
}

func userView(u *store.User) userJSON {
	name, _, _ := strings.Cut(u.Email, "@")
	return userJSON{ID: u.ID, Email: u.Email, Username: name, Name: u.Name, Role: u.Role,
		PlatformAdmin: u.PlatformAdmin, Status: u.Status, TwoStep: u.TOTPEnabled,
		Locked:    u.LockedUntil != nil && u.LockedUntil.After(nowFunc()),
		CreatedAt: u.CreatedAt.Format(timeFormat), PasswordSetAt: u.PasswordChangedAt.Format(timeFormat)}
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.store.UsersInOrganisation(r.Context(), organisation(r).ID)
	if err != nil {
		serverError(w, r, err)
		return
	}
	out := make([]userJSON, len(users))
	for i := range users {
		out[i] = userView(&users[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	org := organisation(r)
	var body struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decode(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	user := normaliseUsername(body.Username)
	if body.Role != "global_admin" {
		body.Role = "member"
	}
	switch {
	case name == "" || len(name) > 200:
		writeFieldError(w, "name", "Enter their name")
		return
	case !usernameRE.MatchString(user):
		writeFieldError(w, "username", usernameHelp)
		return
	}
	if failed := org.PasswordPolicy.Check(body.Password, user); len(failed) > 0 {
		writeFieldError(w, "password", policy.Message(failed))
		return
	}
	created, err := a.store.CreateUser(r.Context(), a.store.DB, store.NewUser{
		OrganisationID: org.ID, Email: user + "@" + org.Domain, Name: name, Role: body.Role,
		PasswordHash: secret.HashPassword(body.Password),
	})
	if isUniqueViolation(err) {
		writeFieldError(w, "username", user+"@"+org.Domain+" already exists.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("account created", "user", created.ID, "organisation", org.ID, "by", caller(r).ID)
	writeJSON(w, http.StatusCreated, userView(created))
}

// target is an account in the organisation in the URL.
func (a *API) target(w http.ResponseWriter, r *http.Request) *store.User {
	u, err := a.store.UserByID(r.Context(), chi.URLParam(r, "userID"))
	if err != nil || u.OrganisationID != organisation(r).ID {
		writeError(w, http.StatusNotFound, "not_found", "That account doesn't exist.")
		return nil
	}
	return u
}

// POST …/reset-password: a new password set by an admin. It unlocks the
// account and signs it out everywhere.
func (a *API) resetPassword(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if failed := organisation(r).PasswordPolicy.Check(body.Password, normaliseUsername(strings.Split(u.Email, "@")[0])); len(failed) > 0 {
		writeFieldError(w, "password", policy.Message(failed))
		return
	}
	if err := a.store.ResetPassword(r.Context(), u.ID, secret.HashPassword(body.Password)); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("password reset", "user", u.ID, "by", caller(r).ID)
	w.WriteHeader(http.StatusNoContent)
}

// POST …/status {status: active|disabled}
func (a *API) setStatus(w http.ResponseWriter, r *http.Request) {
	u := a.target(w, r)
	if u == nil {
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Status != "active" && body.Status != "disabled" {
		writeError(w, http.StatusBadRequest, "bad_request", "Status must be active or disabled.")
		return
	}
	if u.ID == caller(r).ID && body.Status == "disabled" {
		writeError(w, http.StatusConflict, "self", "You can't disable your own account.")
		return
	}
	if err := a.store.SetUserStatus(r.Context(), u.ID, body.Status); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("account status changed", "user", u.ID, "status", body.Status, "by", caller(r).ID)
	w.WriteHeader(http.StatusNoContent)
}

// ── Password policy ──────────────────────────────────────────────────────

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	p := organisation(r).PasswordPolicy
	writeJSON(w, http.StatusOK, map[string]any{"policy": p, "rules": p.Rules(),
		"baselineMinLength": policy.BaselineMinLength})
}

func (a *API) putPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if !decode(w, r, &p) {
		return
	}
	p = p.Normalise()
	if err := a.store.SetPasswordPolicy(r.Context(), organisation(r).ID, p); err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("password policy changed", "organisation", organisation(r).ID, "by", caller(r).ID)
	writeJSON(w, http.StatusOK, map[string]any{"policy": p, "rules": p.Rules(),
		"baselineMinLength": policy.BaselineMinLength})
}

// ── Helpers ──────────────────────────────────────────────────────────────

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message})
}

func writeFieldError(w http.ResponseWriter, field, message string) {
	writeJSON(w, http.StatusUnprocessableEntity, apiError{Error: "invalid", Message: message, Field: field})
}

func serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "admin api error", "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, "server_error", "Something went wrong. Try again.")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Couldn't read the request.")
		return false
	}
	return true
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

const timeFormat = "2006-01-02T15:04:05Z07:00"

var nowFunc = time.Now
