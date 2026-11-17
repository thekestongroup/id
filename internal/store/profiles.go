package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thekestongroup/id/internal/profile"
)

// ── Profiles: built-in fields, managers and custom attributes ────────────
//
// A user's built-in fields are one row in user_profiles (none: all blank).
// Custom attributes are defined per organisation (user_attribute_defs) and
// each value sits in the typed column for its attribute's type
// (user_attribute_values), so both can be filtered in SQL: the dynamic
// groups use them.

var (
	ErrManagerInvalid = errors.New("manager is not someone in this organisation")
	ErrManagerCycle   = errors.New("manager would create a loop")
	ErrAttributeKey   = errors.New("attribute key taken")
)

// ProfileOf returns the user's built-in fields (blank ones if none).
func (s *Store) ProfileOf(ctx context.Context, userID string) (profile.Fields, error) {
	var f profile.Fields
	var manager *string
	var start *time.Time
	err := s.DB.QueryRow(ctx, `SELECT job_title, department, office, phone, mobile, employee_id, manager_id, start_date
		FROM user_profiles WHERE user_id = $1`, userID).
		Scan(&f.JobTitle, &f.Department, &f.Office, &f.Phone, &f.Mobile, &f.EmployeeID, &manager, &start)
	if errors.Is(err, pgx.ErrNoRows) {
		return profile.Fields{}, nil
	}
	if err != nil {
		return f, err
	}
	fill(&f, manager, start)
	return f, nil
}

func fill(f *profile.Fields, manager *string, start *time.Time) {
	if manager != nil {
		f.ManagerID = *manager
	}
	if start != nil {
		f.StartDate = start.Format("2006-01-02")
	}
}

// ProfilesInOrganisation: everyone's built-in fields (people with none are missing).
// A manager who has been deleted counts as none.
func (s *Store) ProfilesInOrganisation(ctx context.Context, orgID string) (map[string]profile.Fields, error) {
	rows, err := s.DB.Query(ctx, `SELECT p.user_id, p.job_title, p.department, p.office, p.phone, p.mobile, p.employee_id,
		CASE WHEN m.status <> 'deleted' THEN p.manager_id END, p.start_date
		FROM user_profiles p JOIN users u ON u.id = p.user_id
		LEFT JOIN users m ON m.id = p.manager_id AND m.organisation_id = u.organisation_id
		WHERE u.organisation_id = $1 AND u.status <> 'deleted'`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]profile.Fields{}
	for rows.Next() {
		var id string
		var f profile.Fields
		var manager *string
		var start *time.Time
		if err := rows.Scan(&id, &f.JobTitle, &f.Department, &f.Office, &f.Phone, &f.Mobile, &f.EmployeeID, &manager, &start); err != nil {
			return nil, err
		}
		fill(&f, manager, start)
		out[id] = f
	}
	return out, rows.Err()
}

// SetProfile saves the user's built-in fields (already normalised). The
// manager has to be another current user of the same organisation, and not
// someone who (however indirectly) reports to this user.
func (s *Store) SetProfile(ctx context.Context, orgID, userID string, f profile.Fields) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.setProfile(ctx, tx, orgID, userID, f); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) setProfile(ctx context.Context, q pgx.Tx, orgID, userID string, f profile.Fields) error {
	var manager *string
	if f.ManagerID != "" {
		if !IsUUID(f.ManagerID) {
			return ErrManagerInvalid
		}
		// One manager change at a time per organisation, so two can't make a loop together.
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "managers:"+orgID); err != nil {
			return err
		}
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND organisation_id = $2
			AND status <> 'deleted')`, f.ManagerID, orgID).Scan(&ok); err != nil {
			return err
		}
		if !ok || f.ManagerID == userID {
			return ErrManagerInvalid
		}
		rows, err := q.Query(ctx, `SELECT p.user_id, p.manager_id FROM user_profiles p JOIN users u ON u.id = p.user_id
			WHERE u.organisation_id = $1 AND p.manager_id IS NOT NULL`, orgID)
		if err != nil {
			return err
		}
		managerOf := map[string]string{}
		for rows.Next() {
			var id, m string
			if err := rows.Scan(&id, &m); err != nil {
				rows.Close()
				return err
			}
			managerOf[id] = m
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if profile.ManagerCycle(managerOf, userID, f.ManagerID) {
			return ErrManagerCycle
		}
		manager = &f.ManagerID
	}
	var start *string
	if f.StartDate != "" {
		start = &f.StartDate
	}
	_, err := q.Exec(ctx, `INSERT INTO user_profiles (user_id, job_title, department, office, phone, mobile, employee_id, manager_id, start_date)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::date)
		ON CONFLICT (user_id) DO UPDATE SET job_title = $2, department = $3, office = $4, phone = $5, mobile = $6,
			employee_id = $7, manager_id = $8, start_date = $9::date, updated_at = now()`,
		userID, f.JobTitle, f.Department, f.Office, f.Phone, f.Mobile, f.EmployeeID, manager, start)
	return err
}

// Report is someone who reports to a manager.
type Report struct {
	ID, Name, Email, JobTitle string
}

func (s *Store) DirectReports(ctx context.Context, managerID string) ([]Report, error) {
	rows, err := s.DB.Query(ctx, `SELECT u.id, u.name, u.email, p.job_title FROM user_profiles p JOIN users u ON u.id = p.user_id
		WHERE p.manager_id = $1 AND u.status <> 'deleted' ORDER BY lower(u.name), u.email`, managerID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Report, error) {
		var x Report
		return x, r.Scan(&x.ID, &x.Name, &x.Email, &x.JobTitle)
	})
}

// NameOf: a user's name and email in the organisation (ErrNotFound if not there or deleted).
func (s *Store) NameOf(ctx context.Context, orgID, userID string) (name, email string, err error) {
	if !IsUUID(userID) {
		return "", "", ErrNotFound
	}
	err = s.DB.QueryRow(ctx, `SELECT name, email FROM users WHERE id = $1 AND organisation_id = $2 AND status <> 'deleted'`,
		userID, orgID).Scan(&name, &email)
	return name, email, notFound(err)
}

// ── Custom attributes ────────────────────────────────────────────────────

type AttributeDef struct {
	ID      string   `json:"id"`
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Choices []string `json:"choices"`
}

func (s *Store) AttributeDefs(ctx context.Context, orgID string) ([]AttributeDef, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, key, label, type, choices FROM user_attribute_defs
		WHERE organisation_id = $1 ORDER BY position, lower(label), key`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AttributeDef, error) {
		var d AttributeDef
		return d, r.Scan(&d.ID, &d.Key, &d.Label, &d.Type, &d.Choices)
	})
}

// MaxAttributes an organisation can define.
const MaxAttributes = 50

var ErrTooManyAttributes = errors.New("too many attributes")

func (s *Store) CreateAttributeDef(ctx context.Context, orgID string, d AttributeDef) (*AttributeDef, error) {
	if d.Choices == nil {
		d.Choices = []string{}
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM user_attribute_defs WHERE organisation_id = $1`, orgID).Scan(&n); err != nil {
		return nil, err
	}
	if n >= MaxAttributes {
		return nil, ErrTooManyAttributes
	}
	err = tx.QueryRow(ctx, `INSERT INTO user_attribute_defs (organisation_id, key, label, type, choices, position)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, orgID, d.Key, d.Label, d.Type, d.Choices, n).Scan(&d.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAttributeKey
		}
		return nil, err
	}
	return &d, tx.Commit(ctx)
}

// UpdateAttributeDef changes the label and, for a choice list, the choices.
// Values no longer in the list are removed. (The key and type are fixed.)
func (s *Store) UpdateAttributeDef(ctx context.Context, orgID, id, label string, choices []string) (*AttributeDef, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var d AttributeDef
	err = tx.QueryRow(ctx, `UPDATE user_attribute_defs SET label = $3,
		choices = CASE WHEN type = 'choice' THEN $4 ELSE choices END, updated_at = now()
		WHERE id = $1 AND organisation_id = $2 RETURNING id, key, label, type, choices`, id, orgID, label, choices).
		Scan(&d.ID, &d.Key, &d.Label, &d.Type, &d.Choices)
	if err != nil {
		return nil, notFound(err)
	}
	if d.Type == profile.TypeChoice {
		if _, err := tx.Exec(ctx, `DELETE FROM user_attribute_values WHERE attribute_id = $1 AND NOT (text_value = ANY($2))`,
			id, choices); err != nil {
			return nil, err
		}
	}
	return &d, tx.Commit(ctx)
}

func (s *Store) DeleteAttributeDef(ctx context.Context, orgID, id string) (*AttributeDef, error) {
	var d AttributeDef
	err := s.DB.QueryRow(ctx, `DELETE FROM user_attribute_defs WHERE id = $1 AND organisation_id = $2
		RETURNING id, key, label, type, choices`, id, orgID).Scan(&d.ID, &d.Key, &d.Label, &d.Type, &d.Choices)
	return &d, notFound(err)
}

// AttributeValues: a user's custom attribute values by attribute key.
func (s *Store) AttributeValues(ctx context.Context, userID string) (map[string]profile.Value, error) {
	m, err := s.attributeValues(ctx, `v.user_id = $1`, userID)
	return m[userID], err
}

// AttributeValuesInOrganisation: everyone's, by user ID then key.
func (s *Store) AttributeValuesInOrganisation(ctx context.Context, orgID string) (map[string]map[string]profile.Value, error) {
	return s.attributeValues(ctx, `d.organisation_id = $1`, orgID)
}

func (s *Store) attributeValues(ctx context.Context, where string, arg any) (map[string]map[string]profile.Value, error) {
	rows, err := s.DB.Query(ctx, `SELECT v.user_id, d.key, v.text_value, v.number_value::float8, v.date_value, v.bool_value
		FROM user_attribute_values v JOIN user_attribute_defs d ON d.id = v.attribute_id WHERE `+where, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]profile.Value{}
	for rows.Next() {
		var uid, key string
		var v profile.Value
		var date *time.Time
		if err := rows.Scan(&uid, &key, &v.Text, &v.Number, &date, &v.Bool); err != nil {
			return nil, err
		}
		if date != nil {
			d := date.Format("2006-01-02")
			v.Date = &d
		}
		if out[uid] == nil {
			out[uid] = map[string]profile.Value{}
		}
		out[uid][key] = v
	}
	return out, rows.Err()
}

// SetAttributeValues saves values by attribute ID (nil: clear it), for
// attributes of the user's organisation (the caller has checked the types).
func (s *Store) SetAttributeValues(ctx context.Context, userID string, values map[string]*profile.Value) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.setAttributeValues(ctx, tx, userID, values); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) setAttributeValues(ctx context.Context, q pgx.Tx, userID string, values map[string]*profile.Value) error {
	for id, v := range values {
		if v == nil {
			if _, err := q.Exec(ctx, `DELETE FROM user_attribute_values WHERE user_id = $1 AND attribute_id = $2`, userID, id); err != nil {
				return err
			}
			continue
		}
		if _, err := q.Exec(ctx, `INSERT INTO user_attribute_values (user_id, attribute_id, text_value, number_value, date_value, bool_value)
			VALUES ($1, $2, $3, $4, $5::date, $6)
			ON CONFLICT (user_id, attribute_id) DO UPDATE SET text_value = $3, number_value = $4, date_value = $5::date, bool_value = $6`,
			userID, id, v.Text, v.Number, v.Date, v.Bool); err != nil {
			return err
		}
	}
	return nil
}

// SaveProfile saves the built-in fields and attribute values together.
func (s *Store) SaveProfile(ctx context.Context, orgID, userID string, f profile.Fields, values map[string]*profile.Value) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.setProfile(ctx, tx, orgID, userID, f); err != nil {
		return err
	}
	if err := s.setAttributeValues(ctx, tx, userID, values); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
