package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ── App access rules ─────────────────────────────────────────────────────
//
// Per organisation and app, like the MFA custom rules (mfa_rules.go): tried
// in order, the first turned-on rule whose conditions all match (users,
// groups, IP addresses; any one value of each; empty matches anyone) gives
// the person's access to the app: forced, enabled or disabled. No rule
// matches: the organisation's default for the app (app_policies), or, for
// Keston's own apps, forced. A condition on the IP address only matches when
// it's known (signing in, not when an admin looks at someone's apps).

type AppRule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"`
	Users    []string `json:"users"`
	Groups   []string `json:"groups"`
	IPRanges []string `json:"ipRanges"`
	// The app it's about. Not in the API's JSON: the URL says which.
	ClientID string `json:"-"`
}

const appRuleColumns = `id::text, name, enabled, mode, user_ids::text[], group_ids::text[], ip_ranges::text[], client_id`

// Matches: whether a rule applies to this user (in these groups), from this
// address.
func (r AppRule) Matches(userID string, groups []string, ip string) bool {
	return matchesPeople(r.Users, r.Groups, r.IPRanges, userID, groups, ip)
}

// ResolveAppMode: the first turned-on rule that matches decides; no match
// gives def.
func ResolveAppMode(def string, rules []AppRule, userID string, groups []string, ip string) string {
	for _, r := range rules {
		if r.Enabled && r.Matches(userID, groups, ip) {
			return r.Mode
		}
	}
	return def
}

// AppRules: an app's rules for the organisation, in order.
func (s *Store) AppRules(ctx context.Context, orgID, clientID string) ([]AppRule, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+appRuleColumns+` FROM app_rules
		WHERE organisation_id = $1 AND client_id = $2 ORDER BY position, created_at`, orgID, clientID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AppRule])
}

// AppRulesByApp: all the organisation's rules, per app, in order.
func (s *Store) AppRulesByApp(ctx context.Context, orgID string) (map[string][]AppRule, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+appRuleColumns+` FROM app_rules
		WHERE organisation_id = $1 ORDER BY client_id, position, created_at`, orgID)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[AppRule])
	out := map[string][]AppRule{}
	for _, r := range list {
		out[r.ClientID] = append(out[r.ClientID], r)
	}
	return out, err
}

// SaveAppRule creates (no ID) or updates a rule for an app; new ones go last.
func (s *Store) SaveAppRule(ctx context.Context, orgID, clientID string, r AppRule) (*AppRule, error) {
	var rows pgx.Rows
	var err error
	if r.ID == "" {
		rows, err = s.DB.Query(ctx, `INSERT INTO app_rules (organisation_id, client_id, name, position, enabled, mode,
				user_ids, group_ids, ip_ranges)
			VALUES ($1, $2, $3, coalesce((SELECT max(position) + 1 FROM app_rules
				WHERE organisation_id = $1 AND client_id = $2), 1), $4, $5, $6::uuid[], $7::uuid[], $8::cidr[])
			RETURNING `+appRuleColumns, orgID, clientID, r.Name, r.Enabled, r.Mode, r.Users, r.Groups, r.IPRanges)
	} else {
		rows, err = s.DB.Query(ctx, `UPDATE app_rules SET name = $4, enabled = $5, mode = $6, user_ids = $7::uuid[],
			group_ids = $8::uuid[], ip_ranges = $9::cidr[], updated_at = now()
			WHERE organisation_id = $1 AND client_id = $2 AND id::text = $3 RETURNING `+appRuleColumns,
			orgID, clientID, r.ID, r.Name, r.Enabled, r.Mode, r.Users, r.Groups, r.IPRanges)
	}
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[AppRule])
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (s *Store) DeleteAppRule(ctx context.Context, orgID, clientID, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM app_rules WHERE organisation_id = $1 AND client_id = $2 AND id::text = $3`,
		orgID, clientID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// OrderAppRules puts an app's rules in this order (every rule's ID, once).
func (s *Store) OrderAppRules(ctx context.Context, orgID, clientID string, ids []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for i, id := range ids {
		tag, err := tx.Exec(ctx, `UPDATE app_rules SET position = $4
			WHERE organisation_id = $1 AND client_id = $2 AND id::text = $3`, orgID, clientID, id, i+1)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit(ctx)
}

// AppRuleCounts: how many rules each of the organisation's apps has.
func (s *Store) AppRuleCounts(ctx context.Context, orgID string) (map[string]int, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id, count(*) FROM app_rules WHERE organisation_id = $1 GROUP BY client_id`, orgID)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	var id string
	var n int
	_, err = pgx.ForEachRow(rows, []any{&id, &n}, func() error { out[id] = n; return nil })
	return out, err
}
