package store

import (
	"context"
	"net/netip"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ── MFA custom rules ─────────────────────────────────────────────────────
//
// Used when an organisation's MFA mode is custom. Tried in order; the first
// enabled rule whose conditions all match decides whether MFA is required.
// Within a condition any value matches (any of these groups); an empty
// condition matches anyone. A condition on the app or IP address only
// matches when it's known (signing in to an app, from an address).

type MFARule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Require  bool     `json:"require"`
	Users    []string `json:"users"`
	Groups   []string `json:"groups"`
	Apps     []string `json:"apps"`
	IPRanges []string `json:"ipRanges"`
}

// SignInContext: what's known about a sign-in, for rules on apps and
// addresses.
type SignInContext struct {
	IP       string
	ClientID string
}

const mfaRuleColumns = `id::text, name, enabled, require_mfa, user_ids::text[], group_ids::text[], client_ids,
	ip_ranges::text[]`

func (s *Store) MFARules(ctx context.Context, orgID string) ([]MFARule, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+mfaRuleColumns+` FROM mfa_rules WHERE organisation_id = $1
		ORDER BY position, created_at`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[MFARule])
}

// SaveMFARule creates (no ID) or updates a rule; new ones go last.
func (s *Store) SaveMFARule(ctx context.Context, orgID string, r MFARule) (*MFARule, error) {
	var rows pgx.Rows
	var err error
	if r.ID == "" {
		rows, err = s.DB.Query(ctx, `INSERT INTO mfa_rules (organisation_id, name, position, enabled, require_mfa,
			user_ids, group_ids, client_ids, ip_ranges)
			VALUES ($1, $2, coalesce((SELECT max(position) + 1 FROM mfa_rules WHERE organisation_id = $1), 1),
				$3, $4, $5::uuid[], $6::uuid[], $7, $8::cidr[])
			RETURNING `+mfaRuleColumns, orgID, r.Name, r.Enabled, r.Require, r.Users, r.Groups, r.Apps, r.IPRanges)
	} else {
		rows, err = s.DB.Query(ctx, `UPDATE mfa_rules SET name = $3, enabled = $4, require_mfa = $5, user_ids = $6::uuid[],
			group_ids = $7::uuid[], client_ids = $8, ip_ranges = $9::cidr[], updated_at = now()
			WHERE organisation_id = $1 AND id::text = $2 RETURNING `+mfaRuleColumns,
			orgID, r.ID, r.Name, r.Enabled, r.Require, r.Users, r.Groups, r.Apps, r.IPRanges)
	}
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[MFARule])
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (s *Store) DeleteMFARule(ctx context.Context, orgID, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM mfa_rules WHERE organisation_id = $1 AND id::text = $2`, orgID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// OrderMFARules puts the organisation's rules in this order (every rule's
// ID, once).
func (s *Store) OrderMFARules(ctx context.Context, orgID string, ids []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for i, id := range ids {
		tag, err := tx.Exec(ctx, `UPDATE mfa_rules SET position = $3 WHERE organisation_id = $1 AND id::text = $2`,
			orgID, id, i+1)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit(ctx)
}

// Matches: whether a rule applies to this user (in these groups), here.
func (r MFARule) Matches(userID string, groups []string, sc SignInContext) bool {
	if len(r.Apps) > 0 && (sc.ClientID == "" || !slices.Contains(r.Apps, sc.ClientID)) {
		return false
	}
	return matchesPeople(r.Users, r.Groups, r.IPRanges, userID, groups, sc.IP)
}

// matchesPeople: the conditions MFA rules and app rules share. Each set
// condition must match (any one of its values); an empty one matches anyone.
// An address condition only matches a known address.
func matchesPeople(users, groups, ipRanges []string, userID string, userGroups []string, ipAddr string) bool {
	if len(users) > 0 && !slices.Contains(users, userID) {
		return false
	}
	if len(groups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(userGroups, g) }) {
		return false
	}
	if len(ipRanges) > 0 {
		ip, err := netip.ParseAddr(ipAddr)
		if err != nil {
			return false
		}
		ip = ip.Unmap()
		if !slices.ContainsFunc(ipRanges, func(c string) bool {
			p, err := netip.ParsePrefix(c)
			return err == nil && p.Contains(ip)
		}) {
			return false
		}
	}
	return true
}

// mfaByRules: the first matching enabled rule's answer, or the default.
func (s *Store) mfaByRules(ctx context.Context, u *User, sc SignInContext, fallback bool) (bool, error) {
	rules, err := s.MFARules(ctx, u.OrganisationID)
	if err != nil {
		return false, err
	}
	groups, err := s.GroupIDsForUser(ctx, u.ID)
	if err != nil {
		return false, err
	}
	for _, r := range rules {
		if r.Enabled && r.Matches(u.ID, groups, sc) {
			return r.Require, nil
		}
	}
	return fallback, nil
}

// MarkMFAEnrolRequired: a rule needs MFA in this session (see
// sessions.mfa_enrol_required).
func (s *Store) MarkMFAEnrolRequired(ctx context.Context, sessionID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE sessions SET mfa_enrol_required = TRUE WHERE id = $1`, sessionID)
	return err
}
