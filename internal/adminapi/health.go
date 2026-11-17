package adminapi

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thekestongroup/id/internal/clientip"
	"github.com/thekestongroup/id/internal/store"
)

// Service health and the message centre (messages.go): written by TKG
// Admins, read by the admins of every organisation.

// isAdmin: someone who uses Keston Admin (so sees health and messages): a
// TKG Admin, a global admin, or anyone whose groups give them permissions.
func isAdmin(r *http.Request) bool {
	u := caller(r)
	return u.PlatformAdmin || u.Role == "global_admin" || len(callerPerms(r)) > 0
}

// needAdmin lets only admins through.
func needAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAdmin(r) {
			writeError(w, http.StatusForbidden, "forbidden", "Only admins can see this.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// needTKG lets only TKG Admins (platform admins) through.
func needTKG(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !caller(r).PlatformAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "Only The Keston Group can do that.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auditPlatform records what a TKG Admin did, in their own organisation's log.
func (a *API) auditPlatform(r *http.Request, action, targetType, id, name, summary string) {
	u := caller(r)
	a.store.Audit(r.Context(), store.AuditEntry{OrganisationID: u.OrganisationID, Actor: u, Action: action,
		TargetType: targetType, TargetID: id, TargetName: name, Summary: summary, IP: clientip.From(r)})
}

func (a *API) healthRoutes(r chi.Router) {
	r.With(needAdmin).Get("/health", a.getHealth)
	r.With(needTKG).Post("/health/incidents", a.createIncident)
	r.With(needTKG).Post("/health/incidents/{id}/updates", a.updateIncident)
	r.With(needTKG).Post("/health/maintenance", a.createMaintenance)
	r.With(needTKG).Put("/health/maintenance/{id}", a.putMaintenance)
	r.With(needTKG).Delete("/health/maintenance/{id}", a.cancelMaintenance)
}

type healthJSON struct {
	Services    []store.ServiceStatus `json:"services"`
	Incidents   []store.Incident      `json:"incidents"`
	Maintenance []store.Maintenance   `json:"maintenance"`
	CanManage   bool                  `json:"canManage"`
}

func (a *API) health(r *http.Request) (*healthJSON, error) {
	now := time.Now()
	incidents, err := a.store.Incidents(r.Context(), now.AddDate(0, 0, -14))
	if err != nil {
		return nil, err
	}
	maintenance, err := a.store.MaintenanceWindows(r.Context(), now)
	if err != nil {
		return nil, err
	}
	if incidents == nil {
		incidents = []store.Incident{}
	}
	if maintenance == nil {
		maintenance = []store.Maintenance{}
	}
	return &healthJSON{store.ServiceStatuses(incidents, maintenance, now), incidents, maintenance, false}, nil
}

// GET /health: each service's status, open and recent incidents (with their
// timelines) and maintenance windows that haven't ended.
func (a *API) getHealth(w http.ResponseWriter, r *http.Request) {
	h, err := a.health(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	h.CanManage = caller(r).PlatformAdmin
	writeJSON(w, http.StatusOK, h)
}

// GET /public/status: the same without the timelines' authors, for anyone
// (a future status page). Rate limited.
func (a *API) publicStatus(w http.ResponseWriter, r *http.Request) {
	h, err := a.health(r)
	if err != nil {
		serverError(w, r, err)
		return
	}
	for i := range h.Incidents {
		for j := range h.Incidents[i].Updates {
			h.Incidents[i].Updates[j].Author = ""
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=30")
	writeJSON(w, http.StatusOK, h)
}

func validIncidentStatus(s string) bool { return slices.Contains(store.IncidentStatuses, s) }

func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	return s, s != "" && len([]rune(s)) <= max
}

// POST /health/incidents {title, impact, status, services, message}
func (a *API) createIncident(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Title    string   `json:"title"`
		Impact   string   `json:"impact"`
		Status   string   `json:"status"`
		Services []string `json:"services"`
		Message  string   `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	title, ok := cleanText(body.Title, 150)
	if !ok {
		writeFieldError(w, "title", "Give the incident a title (up to 150 characters).")
		return
	}
	if body.Impact != "degraded" && body.Impact != "outage" {
		writeFieldError(w, "impact", "Choose degraded or outage.")
		return
	}
	if body.Status == "" {
		body.Status = "investigating"
	}
	if !validIncidentStatus(body.Status) {
		writeFieldError(w, "status", "Choose a status.")
		return
	}
	if !store.ValidServices(body.Services) {
		writeFieldError(w, "services", "Choose at least one service.")
		return
	}
	message, ok := cleanText(body.Message, 2000)
	if !ok {
		writeFieldError(w, "message", "Say what is happening (up to 2,000 characters).")
		return
	}
	inc, err := a.store.CreateIncident(r.Context(), caller(r), title, body.Impact, body.Status, body.Services, message)
	if err != nil {
		serverError(w, r, err)
		return
	}
	slog.Info("incident opened", "incident", inc.ID, "by", caller(r).ID)
	a.auditPlatform(r, store.ActionIncidentOpened, store.TargetIncident, inc.ID, inc.Title,
		"Impact: "+inc.Impact+"; services: "+strings.Join(inc.Services, ", "))
	writeJSON(w, http.StatusCreated, inc)
}

// POST /health/incidents/{id}/updates {status, impact?, message}
func (a *API) updateIncident(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status  string `json:"status"`
		Impact  string `json:"impact"`
		Message string `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !validIncidentStatus(body.Status) {
		writeFieldError(w, "status", "Choose a status.")
		return
	}
	if body.Impact != "" && body.Impact != "degraded" && body.Impact != "outage" {
		writeFieldError(w, "impact", "Choose degraded or outage.")
		return
	}
	message, ok := cleanText(body.Message, 2000)
	if !ok {
		writeFieldError(w, "message", "Say what has changed (up to 2,000 characters).")
		return
	}
	id := chi.URLParam(r, "id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "That incident doesn't exist.")
		return
	}
	inc, err := a.store.UpdateIncident(r.Context(), caller(r), id, body.Status, body.Impact, message)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That incident doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionIncidentUpdated, store.TargetIncident, inc.ID, inc.Title, "Status: "+inc.Status)
	writeJSON(w, http.StatusOK, inc)
}

func maintenanceBody(w http.ResponseWriter, r *http.Request) (store.Maintenance, bool) {
	var body struct {
		Title       string    `json:"title"`
		Description string    `json:"description"`
		Services    []string  `json:"services"`
		StartsAt    time.Time `json:"startsAt"`
		EndsAt      time.Time `json:"endsAt"`
	}
	var m store.Maintenance
	if !decode(w, r, &body) {
		return m, false
	}
	title, ok := cleanText(body.Title, 150)
	if !ok {
		writeFieldError(w, "title", "Give the maintenance a title (up to 150 characters).")
		return m, false
	}
	if len([]rune(body.Description)) > 2000 {
		writeFieldError(w, "description", "Keep the description under 2,000 characters.")
		return m, false
	}
	if !store.ValidServices(body.Services) {
		writeFieldError(w, "services", "Choose at least one service.")
		return m, false
	}
	if body.StartsAt.IsZero() || body.EndsAt.IsZero() || !body.EndsAt.After(body.StartsAt) {
		writeFieldError(w, "endsAt", "It must end after it starts.")
		return m, false
	}
	return store.Maintenance{Title: title, Description: strings.TrimSpace(body.Description), Services: body.Services,
		StartsAt: body.StartsAt, EndsAt: body.EndsAt}, true
}

func (a *API) createMaintenance(w http.ResponseWriter, r *http.Request) {
	m, ok := maintenanceBody(w, r)
	if !ok {
		return
	}
	created, err := a.store.CreateMaintenance(r.Context(), caller(r), m)
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionMaintenanceScheduled, store.TargetMaintenance, created.ID, created.Title,
		"From "+created.StartsAt.UTC().Format(time.RFC3339)+" to "+created.EndsAt.UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) putMaintenance(w http.ResponseWriter, r *http.Request) {
	m, ok := maintenanceBody(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "That maintenance window doesn't exist.")
		return
	}
	updated, err := a.store.UpdateMaintenance(r.Context(), id, m)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That maintenance window doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionMaintenanceUpdated, store.TargetMaintenance, updated.ID, updated.Title, "")
	writeJSON(w, http.StatusOK, updated)
}

func (a *API) cancelMaintenance(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !uuidPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "not_found", "That maintenance window doesn't exist.")
		return
	}
	title, err := a.store.CancelMaintenance(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "That maintenance window doesn't exist.")
		return
	}
	if err != nil {
		serverError(w, r, err)
		return
	}
	a.auditPlatform(r, store.ActionMaintenanceCancelled, store.TargetMaintenance, id, title, "")
	w.WriteHeader(http.StatusNoContent)
}
