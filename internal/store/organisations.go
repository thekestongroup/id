package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thekestongroup/id/internal/policy"
)

type Organisation struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Domain         string         `json:"domain"`
	PasswordPolicy policy.Policy  `json:"passwordPolicy"`
	ProfileEditing ProfileEditing `json:"profileEditing"`
	UserCount      int            `json:"userCount"`
	CreatedAt      time.Time      `json:"createdAt"`
	// The Keston Group's own organisation: can't be deleted.
	IsPlatform bool `json:"isPlatform"`
	// Deletion scheduled: it goes at DeleteAfter unless a global admin signs
	// in first.
	DeletionRequestedAt *time.Time `json:"deletionRequestedAt,omitempty"`
	DeleteAfter         *time.Time `json:"deleteAfter,omitempty"`
}

const orgColumns = `id, name, domain, password_policy, profile_editing,
	(SELECT count(*) FROM users u WHERE u.organisation_id = organisations.id AND u.support_for IS NULL
		AND u.status <> 'deleted'), created_at,
	is_platform, deletion_requested_at, delete_after`

func scanOrganisation(row pgx.Row) (*Organisation, error) {
	var o Organisation
	var raw, editing []byte
	if err := row.Scan(&o.ID, &o.Name, &o.Domain, &raw, &editing, &o.UserCount, &o.CreatedAt, &o.IsPlatform,
		&o.DeletionRequestedAt, &o.DeleteAfter); err != nil {
		return nil, notFound(err)
	}
	if err := json.Unmarshal(raw, &o.PasswordPolicy); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(editing, &o.ProfileEditing); err != nil {
		return nil, err
	}
	o.PasswordPolicy = o.PasswordPolicy.Normalise()
	return &o, nil
}

func (s *Store) Organisations(ctx context.Context) ([]Organisation, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+orgColumns+` FROM organisations ORDER BY is_platform DESC, name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Organisation, error) {
		o, err := scanOrganisation(r)
		if err != nil {
			return Organisation{}, err
		}
		return *o, nil
	})
}

func (s *Store) OrganisationByID(ctx context.Context, id string) (*Organisation, error) {
	return scanOrganisation(s.DB.QueryRow(ctx, `SELECT `+orgColumns+` FROM organisations WHERE id = $1`, id))
}

func (s *Store) OrganisationByDomain(ctx context.Context, domain string) (*Organisation, error) {
	return scanOrganisation(s.DB.QueryRow(ctx, `SELECT `+orgColumns+` FROM organisations
		WHERE lower(domain) = lower($1)`, domain))
}

func (s *Store) DomainTaken(ctx context.Context, domain string) (bool, error) {
	var taken bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organisations WHERE lower(domain) = lower($1))`,
		domain).Scan(&taken)
	return taken, err
}

// CreateOrganisation makes an organisation and its first global admin
// together: neither exists without the other.
func (s *Store) CreateOrganisation(ctx context.Context, name, domain string, admin NewUser) (*Organisation, *User,
	error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	var orgID string
	if err := tx.QueryRow(ctx, `INSERT INTO organisations (name, domain) VALUES ($1, lower($2)) RETURNING id`,
		name, domain).Scan(&orgID); err != nil {
		return nil, nil, err
	}
	admin.OrganisationID = orgID
	admin.Role = "global_admin"
	user, err := s.CreateUser(ctx, tx, admin)
	if err != nil {
		return nil, nil, err
	}
	// Its first admin has every product.
	if _, err := tx.Exec(ctx, `INSERT INTO user_licences (user_id, client_id)
		SELECT $1, id FROM clients WHERE builtin`, user.ID); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	org, err := s.OrganisationByID(ctx, orgID)
	return org, user, err
}

func (s *Store) SetPasswordPolicy(ctx context.Context, orgID string, p policy.Policy) error {
	raw, err := json.Marshal(p.Normalise())
	if err != nil {
		return err
	}
	tag, err := s.DB.Exec(ctx, `UPDATE organisations SET password_policy = $2, updated_at = now() WHERE id = $1`,
		orgID, raw)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// PolicyFor is the password policy that applies to an organisation's
// accounts (baseline only if it can't be found).
func (s *Store) PolicyFor(ctx context.Context, orgID string) policy.Policy {
	if o, err := s.OrganisationByID(ctx, orgID); err == nil {
		return o.PasswordPolicy
	}
	return policy.Policy{}.Normalise()
}

// ProfileEditing is which profile fields an organisation's people may
// change themselves in Keston ID.
type ProfileEditing struct {
	Name    bool `json:"name"`
	Email   bool `json:"email"`
	Picture bool `json:"picture"`
}

func (s *Store) SetProfileEditing(ctx context.Context, orgID string, p ProfileEditing) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `UPDATE organisations SET profile_editing = $2, updated_at = now() WHERE id = $1`, orgID, raw)
	return err
}

// ── The platform organisation (The Keston Group) ─────────────────────────

// EnsurePlatformOrganisation makes sure The Keston Group's organisation
// exists (there must always be one): marks the organisation with this
// domain, or creates it (with no users yet).
func (s *Store) EnsurePlatformOrganisation(ctx context.Context, name, domain string) (*Organisation, error) {
	var id string
	// Already there: keep its name and domain in line with the config.
	err := s.DB.QueryRow(ctx, `UPDATE organisations SET name = $1, domain = lower($2) WHERE is_platform
		RETURNING id`, name, domain).Scan(&id)
	if err == nil {
		return s.OrganisationByID(ctx, id)
	}
	if err := s.DB.QueryRow(ctx, `INSERT INTO organisations (name, domain, is_platform) VALUES ($1, lower($2), TRUE)
		ON CONFLICT (lower(domain)) DO UPDATE SET is_platform = TRUE RETURNING id`, name, domain).Scan(&id); err != nil {
		return nil, err
	}
	return s.OrganisationByID(ctx, id)
}

// ── Deleting an organisation ─────────────────────────────────────────────

// DeletionWait is how long a deletion waits, so a mistake (or someone who
// shouldn't) can be undone by a global admin signing in.
const DeletionWait = 14 * 24 * time.Hour

func (s *Store) ScheduleDeletion(ctx context.Context, orgID, userID string) (time.Time, error) {
	var after time.Time
	err := s.DB.QueryRow(ctx, `UPDATE organisations SET deletion_requested_at = now(), deletion_requested_by = $2,
		delete_after = now() + $3::interval WHERE id = $1 AND NOT is_platform RETURNING delete_after`,
		orgID, userID, DeletionWait).Scan(&after)
	return after, notFound(err)
}

// CancelDeletion: returns whether a deletion was waiting.
func (s *Store) CancelDeletion(ctx context.Context, orgID string) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE organisations SET deletion_requested_at = NULL, deletion_requested_by = NULL,
		delete_after = NULL WHERE id = $1 AND delete_after IS NOT NULL`, orgID)
	return tag.RowsAffected() == 1, err
}

// DeleteDueOrganisations deletes organisations whose 14 days are up: their
// users (and so their sessions, tokens and grants) first, then the rest.
func (s *Store) DeleteDueOrganisations(ctx context.Context) ([]string, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT name FROM organisations
		WHERE delete_after <= now() AND NOT is_platform FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(names) == 0 {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE organisation_id IN
		(SELECT id FROM organisations WHERE delete_after <= now() AND NOT is_platform)`); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM organisations WHERE delete_after <= now() AND NOT is_platform`); err != nil {
		return nil, err
	}
	return names, tx.Commit(ctx)
}
