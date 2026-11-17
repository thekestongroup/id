package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Services shown on the health page.
var Services = []string{"keston-id", "keston-admin", "keston-forms", "learn", "work", "apps"}

func ValidServices(ids []string) bool {
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !slices.Contains(Services, id) {
			return false
		}
	}
	return true
}

var IncidentStatuses = []string{"investigating", "identified", "monitoring", "resolved"}

// Service statuses.
const (
	StatusOperational = "operational"
	StatusDegraded    = "degraded"
	StatusOutage      = "outage"
	StatusMaintenance = "maintenance"
)

type IncidentUpdate struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"createdAt"`
}

type Incident struct {
	ID         string           `json:"id"`
	Title      string           `json:"title"`
	Impact     string           `json:"impact"`
	Status     string           `json:"status"`
	Services   []string         `json:"services"`
	CreatedAt  time.Time        `json:"createdAt"`
	ResolvedAt *time.Time       `json:"resolvedAt"`
	Updates    []IncidentUpdate `json:"updates"`
}

// Active: not resolved yet.
func (i Incident) Active() bool { return i.Status != "resolved" }

type Maintenance struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Services    []string  `json:"services"`
	StartsAt    time.Time `json:"startsAt"`
	EndsAt      time.Time `json:"endsAt"`
	Cancelled   bool      `json:"cancelled"`
}

// ServiceStatus is one service's state now.
type ServiceStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// ServiceStatuses works out each service's status: the worst open incident,
// else maintenance under way, else operational.
func ServiceStatuses(incidents []Incident, maintenance []Maintenance, now time.Time) []ServiceStatus {
	out := make([]ServiceStatus, len(Services))
	for i, id := range Services {
		status := StatusOperational
		for _, m := range maintenance {
			if !m.Cancelled && slices.Contains(m.Services, id) && !now.Before(m.StartsAt) && now.Before(m.EndsAt) {
				status = StatusMaintenance
			}
		}
		for _, inc := range incidents {
			if !inc.Active() || !slices.Contains(inc.Services, id) {
				continue
			}
			if inc.Impact == "outage" {
				status = StatusOutage
			} else if status != StatusOutage {
				status = StatusDegraded
			}
		}
		out[i] = ServiceStatus{id, status}
	}
	return out
}

const incidentCols = `id, title, impact, status, services, created_at, resolved_at`

func (s *Store) loadUpdates(ctx context.Context, incs []Incident) error {
	if len(incs) == 0 {
		return nil
	}
	ids := make([]string, len(incs))
	byID := map[string]*Incident{}
	for i := range incs {
		ids[i] = incs[i].ID
		incs[i].Updates = []IncidentUpdate{}
		byID[incs[i].ID] = &incs[i]
	}
	rows, err := s.DB.Query(ctx, `SELECT incident_id, id, status, message, author_name, created_at
		FROM service_incident_updates WHERE incident_id = ANY($1::uuid[]) ORDER BY created_at DESC, id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var incID string
		var u IncidentUpdate
		if err := rows.Scan(&incID, &u.ID, &u.Status, &u.Message, &u.Author, &u.CreatedAt); err != nil {
			return err
		}
		byID[incID].Updates = append(byID[incID].Updates, u)
	}
	return rows.Err()
}

// Incidents: every open one, and the ones resolved since `since`, newest first.
func (s *Store) Incidents(ctx context.Context, since time.Time) ([]Incident, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+incidentCols+` FROM service_incidents
		WHERE resolved_at IS NULL OR resolved_at >= $1 ORDER BY created_at DESC LIMIT 100`, since)
	if err != nil {
		return nil, err
	}
	incs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[incidentRow])
	if err != nil {
		return nil, err
	}
	out := make([]Incident, len(incs))
	for i, r := range incs {
		out[i] = Incident(r)
		out[i].Updates = nil
	}
	return out, s.loadUpdates(ctx, out)
}

// incidentRow matches incidentCols (Incident has Updates last).
type incidentRow struct {
	ID         string
	Title      string
	Impact     string
	Status     string
	Services   []string
	CreatedAt  time.Time
	ResolvedAt *time.Time
	Updates    []IncidentUpdate `db:"-"`
}

func (s *Store) Incident(ctx context.Context, id string) (*Incident, error) {
	var r incidentRow
	err := s.DB.QueryRow(ctx, `SELECT `+incidentCols+` FROM service_incidents WHERE id = $1`, id).
		Scan(&r.ID, &r.Title, &r.Impact, &r.Status, &r.Services, &r.CreatedAt, &r.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	inc := Incident(r)
	list := []Incident{inc}
	if err := s.loadUpdates(ctx, list); err != nil {
		return nil, err
	}
	return &list[0], nil
}

// CreateIncident opens an incident with its first update.
func (s *Store) CreateIncident(ctx context.Context, by *User, title, impact, status string, services []string, message string) (*Incident, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var id string
	if err := tx.QueryRow(ctx, `INSERT INTO service_incidents (title, impact, status, services, created_by, resolved_at)
		VALUES ($1, $2, $3, $4, $5, CASE WHEN $3 = 'resolved' THEN now() END) RETURNING id`,
		title, impact, status, services, by.ID).Scan(&id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO service_incident_updates (incident_id, status, message, author_name)
		VALUES ($1, $2, $3, $4)`, id, status, message, by.Name); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Incident(ctx, id)
}

// UpdateIncident adds a timeline entry, moving the incident to its status
// and, if given, changing its impact.
func (s *Store) UpdateIncident(ctx context.Context, by *User, id, status, impact, message string) (*Incident, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE service_incidents SET status = $2, impact = COALESCE(NULLIF($3, ''), impact),
		resolved_at = CASE WHEN $2 = 'resolved' THEN COALESCE(resolved_at, now()) END WHERE id = $1`, id, status, impact)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx, `INSERT INTO service_incident_updates (incident_id, status, message, author_name)
		VALUES ($1, $2, $3, $4)`, id, status, message, by.Name); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Incident(ctx, id)
}

// MaintenanceWindows: not cancelled, ending after `since`, soonest first.
func (s *Store) MaintenanceWindows(ctx context.Context, since time.Time) ([]Maintenance, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, title, description, services, starts_at, ends_at, cancelled
		FROM maintenance_windows WHERE ends_at >= $1 AND NOT cancelled ORDER BY starts_at LIMIT 100`, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Maintenance])
}

func (s *Store) CreateMaintenance(ctx context.Context, by *User, m Maintenance) (*Maintenance, error) {
	err := s.DB.QueryRow(ctx, `INSERT INTO maintenance_windows (title, description, services, starts_at, ends_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, m.Title, m.Description, m.Services, m.StartsAt, m.EndsAt, by.ID).Scan(&m.ID)
	return &m, err
}

func (s *Store) UpdateMaintenance(ctx context.Context, id string, m Maintenance) (*Maintenance, error) {
	err := s.DB.QueryRow(ctx, `UPDATE maintenance_windows SET title = $2, description = $3, services = $4, starts_at = $5, ends_at = $6
		WHERE id = $1 AND NOT cancelled RETURNING id`, id, m.Title, m.Description, m.Services, m.StartsAt, m.EndsAt).Scan(&m.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

func (s *Store) CancelMaintenance(ctx context.Context, id string) (string, error) {
	var title string
	err := s.DB.QueryRow(ctx, `UPDATE maintenance_windows SET cancelled = TRUE WHERE id = $1 AND NOT cancelled RETURNING title`, id).Scan(&title)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return title, err
}
