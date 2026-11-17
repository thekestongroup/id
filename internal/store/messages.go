package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var MessageCategories = []string{"feature", "change", "action_required", "notice"}

// Message is an announcement from Keston. Body is Markdown: Keston Admin
// renders a safe subset, never raw HTML.
type Message struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	Body             string     `json:"body"`
	Category         string     `json:"category"`
	ActionBy         *time.Time `json:"actionBy"`
	AllOrganisations bool       `json:"allOrganisations"`
	OrganisationIDs  []string   `json:"organisationIds"`
	Author           string     `json:"author"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// UserMessage is a message as one admin sees it.
type UserMessage struct {
	Message
	Read     bool `json:"read"`
	Archived bool `json:"archived"`
}

const messageCols = `m.id, m.title, m.body, m.category, m.action_by, m.all_organisations,
	m.organisation_ids::text[], m.author_name, m.created_at, m.updated_at`

// A message reaches an organisation if it targets all or lists it ($1).
const targeted = `(m.all_organisations OR $1::uuid = ANY(m.organisation_ids))`

func (s *Store) CreateMessage(ctx context.Context, by *User, m Message) (*Message, error) {
	if m.OrganisationIDs == nil {
		m.OrganisationIDs = []string{}
	}
	err := s.DB.QueryRow(ctx, `INSERT INTO messages (title, body, category, action_by, all_organisations,
			organisation_ids, created_by, author_name) VALUES ($1, $2, $3, $4, $5, $6::uuid[], $7, $8)
		RETURNING id, created_at, updated_at`, m.Title, m.Body, m.Category, m.ActionBy, m.AllOrganisations,
		m.OrganisationIDs, by.ID, by.Name).Scan(&m.ID, &m.CreatedAt, &m.UpdatedAt)
	m.Author = by.Name
	return &m, err
}

func (s *Store) UpdateMessage(ctx context.Context, id string, m Message) (*Message, error) {
	if m.OrganisationIDs == nil {
		m.OrganisationIDs = []string{}
	}
	err := s.DB.QueryRow(ctx, `UPDATE messages SET title = $2, body = $3, category = $4, action_by = $5,
			all_organisations = $6, organisation_ids = $7::uuid[], updated_at = now() WHERE id = $1
		RETURNING id, author_name, created_at, updated_at`, id, m.Title, m.Body, m.Category, m.ActionBy,
		m.AllOrganisations, m.OrganisationIDs).Scan(&m.ID, &m.Author, &m.CreatedAt, &m.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

func (s *Store) DeleteMessage(ctx context.Context, id string) (string, error) {
	var title string
	err := s.DB.QueryRow(ctx, `DELETE FROM messages WHERE id = $1 RETURNING title`, id).Scan(&title)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return title, err
}

// AllMessages: everything posted, for the people who post (TKG Admins).
func (s *Store) AllMessages(ctx context.Context) ([]Message, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+messageCols+` FROM messages m ORDER BY m.created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Message])
}

// MessagesFor: what reaches this admin (through their organisation), newest
// first, with their read and archived state.
func (s *Store) MessagesFor(ctx context.Context, orgID, userID string) ([]UserMessage, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+messageCols+`,
			COALESCE(st.read_at IS NOT NULL, FALSE), COALESCE(st.archived_at IS NOT NULL, FALSE)
		FROM messages m LEFT JOIN message_states st ON st.message_id = m.id AND st.user_id = $2
		WHERE `+targeted+` ORDER BY m.created_at DESC LIMIT 200`, orgID, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UserMessage])
}

// MessageReaches: whether this message is for the organisation.
func (s *Store) MessageReaches(ctx context.Context, id, orgID string) (bool, error) {
	var ok bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM messages m WHERE m.id = $2 AND `+targeted+`)`, orgID, id).Scan(&ok)
	return ok, err
}

// SetMessageState sets one admin's read and/or archived state (nil: leave).
func (s *Store) SetMessageState(ctx context.Context, id, userID string, read, archived *bool) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO message_states (message_id, user_id, read_at, archived_at)
		VALUES ($1, $2, CASE WHEN $3::bool THEN now() END, CASE WHEN $4::bool THEN now() END)
		ON CONFLICT (message_id, user_id) DO UPDATE SET
			read_at = CASE WHEN $3::bool IS NULL THEN message_states.read_at WHEN $3::bool THEN COALESCE(message_states.read_at, now()) END,
			archived_at = CASE WHEN $4::bool IS NULL THEN message_states.archived_at WHEN $4::bool THEN COALESCE(message_states.archived_at, now()) END`,
		id, userID, read, archived)
	return err
}

// MessageAudienceAdmins: the active global admins of the organisations this
// message is for (the people to put it in the bell for).
func (s *Store) MessageAudienceAdmins(ctx context.Context, m Message) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT id FROM users WHERE role = 'global_admin' AND status = 'active'
		AND ($1 OR organisation_id = ANY($2::uuid[]))`, m.AllOrganisations, m.OrganisationIDs)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// OrganisationsExist: every ID is an organisation.
func (s *Store) OrganisationsExist(ctx context.Context, ids []string) (bool, error) {
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM organisations WHERE id = ANY($1::uuid[])`, ids).Scan(&n); err != nil {
		return false, err
	}
	return n == len(ids), nil
}
