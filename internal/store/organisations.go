package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/thekestongroup/id/internal/policy"
)

type Organisation struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	Domain         string        `json:"domain"`
	PasswordPolicy policy.Policy `json:"passwordPolicy"`
	UserCount      int           `json:"userCount"`
	CreatedAt      time.Time     `json:"createdAt"`
}

const orgColumns = `id, name, domain, password_policy,
	(SELECT count(*) FROM users u WHERE u.organisation_id = organisations.id), created_at`

func scanOrganisation(row pgx.Row) (*Organisation, error) {
	var o Organisation
	var raw []byte
	if err := row.Scan(&o.ID, &o.Name, &o.Domain, &raw, &o.UserCount, &o.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	if err := json.Unmarshal(raw, &o.PasswordPolicy); err != nil {
		return nil, err
	}
	o.PasswordPolicy = o.PasswordPolicy.Normalise()
	return &o, nil
}

func (s *Store) Organisations(ctx context.Context) ([]Organisation, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+orgColumns+` FROM organisations ORDER BY name`)
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
