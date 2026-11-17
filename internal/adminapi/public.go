package adminapi

import (
	"github.com/thekestongroup/id/internal/clientip"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/profile"
	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// Self-service sign-up (admin.keston.co/create-organisation): anyone can
// create an organisation, becoming its first global admin. No sign-in, so
// these routes are rate limited per address.
func (a *API) PublicRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(noStore)
	checks := newLimiter(60, time.Minute) // as you type in the wizard
	creates := newLimiter(5, time.Hour)
	r.With(checks.middleware).Get("/domains/{domain}", a.domainAvailable)
	r.With(checks.middleware).Post("/password-check", a.publicPasswordCheck)
	r.With(creates.middleware).Post("/organisations", a.signUp)
	return r
}

// The baseline rules only: a new organisation has no rules of its own yet.
func (a *API) publicPasswordCheck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Username string `json:"username"`
	}
	if !decode(w, r, &body) {
		return
	}
	failed := map[string]bool{}
	for _, f := range (policy.Policy{}).Check(body.Password, normaliseUsername(body.Username)) {
		failed[f.ID] = true
	}
	out := []ruleResult{}
	for _, rule := range (policy.Policy{}).Rules() {
		out = append(out, ruleResult{Rule: rule, Met: body.Password != "" && !failed[rule.ID]})
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /public/organisations: create an organisation and its first global
// admin, who then signs in to Keston Admin.
func (a *API) signUp(w http.ResponseWriter, r *http.Request) {
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
	user := profile.NormaliseUsername(body.AdminUsername)
	adminName := strings.TrimSpace(body.AdminName)
	switch {
	case name == "" || len(name) > 200:
		writeFieldError(w, "name", "Enter the organisation's name")
		return
	case !validDomain(domain):
		writeFieldError(w, "domain", domainHelp)
		return
	case !profile.ValidName(adminName):
		writeFieldError(w, "adminName", "Enter the global admin's name")
		return
	case !profile.ValidUsername(user):
		writeFieldError(w, "adminUsername", profile.UsernameHelp)
		return
	}
	if failed := (policy.Policy{}).Check(body.AdminPassword, user, name); len(failed) > 0 {
		writeFieldError(w, "adminPassword", policy.Message(failed))
		return
	}
	// Unverified (no one can sign in yet) while Keston staff verify new
	// organisations: Settings → Require verification for new organisations.
	require, err := a.store.RequireOrganisationVerification(r.Context())
	if err != nil {
		serverError(w, r, err)
		return
	}
	org, admin, err := a.store.CreateOrganisationWith(r.Context(), name, domain, store.NewUser{
		Email: user + "@" + domain, Name: adminName, PasswordHash: secret.HashPassword(body.AdminPassword),
	}, !require)
	if isUniqueViolation(err) {
		writeFieldError(w, "domain", domain+" already belongs to another organisation.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("organisation signed up", "organisation", org.ID, "domain", domain, "ip", clientip.From(r))
	a.store.Audit(r.Context(), store.AuditEntry{OrganisationID: org.ID, Actor: admin,
		Action: store.ActionOrganisationCreated, TargetType: store.TargetOrganisation, TargetID: org.ID,
		TargetName: org.Name, Summary: "Signed up", IP: clientip.From(r)})
	writeJSON(w, http.StatusCreated, map[string]any{"organisation": org, "admin": a.userView(admin),
		"awaitingVerification": !org.Verified})
}

// ── Rate limiting ────────────────────────────────────────────────────────

// limiter allows n requests per window per address, on this replica (so a
// little more across several replicas; enough to stop scripted abuse).
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	seen   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, seen: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if now.Sub(t) < l.window {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.n {
		l.seen[key] = recent
		return false
	}
	l.seen[key] = append(recent, now)
	if len(l.seen) > 10000 { // forget everyone if it grows too big
		l.seen = map[string][]time.Time{key: l.seen[key]}
	}
	return true
}

func (l *limiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientip.From(r)) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many tries. Wait a little and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}
