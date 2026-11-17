package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/thekestongroup/id/internal/secret"
)

// An organisation can have several domains (organisation_domains). Exactly
// one is primary (new users' default; organisations.domain is a copy of it),
// and only verified domains can be used in users' emails. A domain belongs
// to one organisation in all of Keston, verified or not.

var (
	ErrDomainTaken     = errors.New("domain belongs to an organisation already")
	ErrDomainInUse     = errors.New("people still use that domain")
	ErrDomainPrimary   = errors.New("that is the primary domain")
	ErrDomainUnverif   = errors.New("domain isn't verified")
	ErrRenameConflicts = errors.New("renaming would clash with existing emails")
)

type OrgDomain struct {
	ID             string     `json:"id"`
	OrganisationID string     `json:"-"`
	Domain         string     `json:"domain"`
	Primary        bool       `json:"primary"`
	Verified       bool       `json:"verified"`
	Token          string     `json:"-"`
	VerifiedAt     *time.Time `json:"verifiedAt,omitempty"`
	VerifiedByName string     `json:"verifiedByName,omitempty"`
	// Verified by a TKG Admin without DNS.
	Override  bool      `json:"override"`
	CreatedAt time.Time `json:"createdAt"`
	// People whose email uses it.
	UserCount int `json:"userCount"`
}

const domainColumns = `d.id::text, d.organisation_id::text, d.domain, d.is_primary, d.status = 'verified',
	d.verification_token, d.verified_at, d.verified_by_name, d.verified_by_override, d.created_at,
	(SELECT count(*) FROM users u WHERE u.organisation_id = d.organisation_id AND u.status <> 'deleted'
		AND u.support_for IS NULL AND lower(u.email) LIKE '%@' || d.domain)`

func scanDomain(row pgx.Row) (*OrgDomain, error) {
	var d OrgDomain
	if err := row.Scan(&d.ID, &d.OrganisationID, &d.Domain, &d.Primary, &d.Verified, &d.Token, &d.VerifiedAt,
		&d.VerifiedByName, &d.Override, &d.CreatedAt, &d.UserCount); err != nil {
		return nil, notFound(err)
	}
	return &d, nil
}

// VerificationRecord is the TXT record that proves control of the domain:
// name and value. (The same value at the domain itself also counts.)
func (d *OrgDomain) VerificationRecord() (name, value string) {
	return "_keston-verification." + d.Domain, "keston-verify=" + d.Token
}

// OrganisationDomains: its domains, the primary first.
func (s *Store) OrganisationDomains(ctx context.Context, orgID string) ([]OrgDomain, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+domainColumns+` FROM organisation_domains d
		WHERE d.organisation_id = $1 ORDER BY d.is_primary DESC, d.domain`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OrgDomain, error) {
		d, err := scanDomain(r)
		if err != nil {
			return OrgDomain{}, err
		}
		return *d, nil
	})
}

// VerifiedDomains: the domains its users' emails can have, the primary first.
func (s *Store) VerifiedDomains(ctx context.Context, orgID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT domain FROM organisation_domains
		WHERE organisation_id = $1 AND status = 'verified' ORDER BY is_primary DESC, domain`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// OrganisationDomain: one of the organisation's domains.
func (s *Store) OrganisationDomain(ctx context.Context, orgID, id string) (*OrgDomain, error) {
	if !IsUUID(id) {
		return nil, ErrNotFound
	}
	return scanDomain(s.DB.QueryRow(ctx, `SELECT `+domainColumns+` FROM organisation_domains d
		WHERE d.organisation_id = $1 AND d.id = $2`, orgID, id))
}

// AddDomain: adds a domain to the organisation, unverified (with its token
// to prove it), or verified straight away by a TKG Admin (override). With no
// domain yet it can only be an override or the first. ErrDomainTaken if any
// organisation has it.
func (s *Store) AddDomain(ctx context.Context, orgID, domain string, by *User, override bool) (*OrgDomain, error) {
	domain = strings.ToLower(domain)
	var id string
	err := s.DB.QueryRow(ctx, `INSERT INTO organisation_domains (organisation_id, domain, status, verification_token,
			verified_at, verified_by, verified_by_name, verified_by_override, added_by)
		VALUES ($1, $2, CASE WHEN $4 THEN 'verified' ELSE 'unverified' END, $3,
			CASE WHEN $4 THEN now() END, CASE WHEN $4 THEN $5::uuid END, CASE WHEN $4 THEN $6 ELSE '' END, $4, $5::uuid)
		RETURNING id::text`, orgID, domain, secret.Token(), override, by.ID, by.Name).Scan(&id)
	if isUnique(err) {
		return nil, ErrDomainTaken
	}
	if err != nil {
		return nil, err
	}
	return s.OrganisationDomain(ctx, orgID, id)
}

// MarkDomainVerified records that DNS proved the domain (idempotent: false if
// it was verified already).
func (s *Store) MarkDomainVerified(ctx context.Context, orgID, id string, by *User) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE organisation_domains SET status = 'verified', verified_at = now(),
		verified_by = $3, verified_by_name = $4 WHERE organisation_id = $1 AND id = $2 AND status = 'unverified'`,
		orgID, id, by.ID, by.Name)
	return tag.RowsAffected() > 0, err
}

// RemoveDomain deletes a domain that isn't primary and that nobody's email
// uses.
func (s *Store) RemoveDomain(ctx context.Context, orgID, id string) error {
	d, err := s.OrganisationDomain(ctx, orgID, id)
	if err != nil {
		return err
	}
	switch {
	case d.Primary:
		return ErrDomainPrimary
	case d.UserCount > 0:
		return ErrDomainInUse
	}
	// Deleted accounts still keep their email for restoring: they count too.
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE organisation_id = $1 AND lower(email) LIKE '%@' || $2`,
		orgID, d.Domain).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrDomainInUse
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM organisation_domains WHERE id = $1 AND NOT is_primary`, id)
	return err
}

// SetPrimaryDomain makes a verified domain the primary one (and keeps
// organisations.domain in step). Existing users keep their emails, unless
// renameUsers: then everyone not already on it (except support accounts)
// moves to it, keeping their usernames; ErrRenameConflicts if that would
// give two people the same email. Returns how many were renamed.
func (s *Store) SetPrimaryDomain(ctx context.Context, orgID, id string, renameUsers bool) (int, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var domain string
	var verified bool
	err = tx.QueryRow(ctx, `SELECT domain, status = 'verified' FROM organisation_domains
		WHERE organisation_id = $1 AND id = $2 FOR UPDATE`, orgID, id).Scan(&domain, &verified)
	if err != nil {
		return 0, notFound(err)
	}
	if !verified {
		return 0, ErrDomainUnverif
	}
	if _, err := tx.Exec(ctx, `UPDATE organisation_domains SET is_primary = FALSE WHERE organisation_id = $1 AND is_primary`,
		orgID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE organisation_domains SET is_primary = TRUE WHERE id = $1`, id); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE organisations SET domain = $2, updated_at = now() WHERE id = $1`, orgID, domain); err != nil {
		return 0, err
	}
	renamed := 0
	if renameUsers {
		var clashes int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users u JOIN users o
			ON lower(o.email) = lower(split_part(u.email, '@', 1)) || '@' || $2 AND o.id <> u.id
			WHERE u.organisation_id = $1 AND u.support_for IS NULL AND lower(u.email) NOT LIKE '%@' || $2`,
			orgID, domain).Scan(&clashes); err != nil {
			return 0, err
		}
		if clashes > 0 {
			return 0, ErrRenameConflicts
		}
		tag, err := tx.Exec(ctx, `UPDATE users SET email = lower(split_part(email, '@', 1)) || '@' || $2, updated_at = now()
			WHERE organisation_id = $1 AND support_for IS NULL AND lower(email) NOT LIKE '%@' || $2`, orgID, domain)
		if err != nil {
			return 0, err
		}
		renamed = int(tag.RowsAffected())
	}
	return renamed, tx.Commit(ctx)
}

// insertPrimaryDomain adds an organisation's first domain (verified,
// primary) in the same transaction that creates it.
func insertPrimaryDomain(ctx context.Context, q pgx.Tx, orgID, domain string) error {
	_, err := q.Exec(ctx, `INSERT INTO organisation_domains (organisation_id, domain, is_primary, status,
		verification_token, verified_at) VALUES ($1, lower($2), TRUE, 'verified', $3, now())`,
		orgID, domain, secret.Token())
	return err
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
