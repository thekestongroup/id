package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Groups ───────────────────────────────────────────────────────────────

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	MemberCount int       `json:"memberCount"`
	CreatedAt   time.Time `json:"createdAt"`
	// What its users can do in Keston Admin (see permissions.go).
	Permissions []string `json:"permissions"`
}

const groupColumns = `g.id, g.name, (SELECT count(*) FROM group_members m JOIN users u ON u.id = m.user_id
		WHERE m.group_id = g.id AND u.status <> 'deleted'), g.created_at,
	ARRAY(SELECT p.permission FROM group_permissions p WHERE p.group_id = g.id ORDER BY p.permission)`

func (s *Store) Groups(ctx context.Context, orgID string) ([]Group, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+groupColumns+` FROM groups g WHERE g.organisation_id = $1
		ORDER BY lower(g.name)`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Group])
}

// GroupFilter narrows and orders the groups list. Zero values: no filter,
// by name.
type GroupFilter struct {
	// Part of the name.
	Q string
	// Members compares the member count (Op: gt, gte, lt, lte or eq) with N.
	Members *MemberCount
	// Gives permissions in Keston Admin (true) or none (false).
	Permissions *bool
	// Sort is name, members, permissions (how many) or created.
	Sort string
	Desc bool
}

type MemberCount struct {
	Op string
	N  int
}

var memberOps = map[string]string{"gt": ">", "gte": ">=", "lt": "<", "lte": "<=", "eq": "="}

// IsMemberOp: op is one MemberCount understands.
func IsMemberOp(op string) bool { _, ok := memberOps[op]; return ok }

// GroupSorts are what GroupFilter.Sort can be.
var GroupSorts = []string{"name", "members", "permissions", "created"}

// GroupsFiltered lists an organisation's groups, filtered and sorted in SQL.
func (s *Store) GroupsFiltered(ctx context.Context, orgID string, f GroupFilter) ([]Group, error) {
	w := &where{}
	w.add("g.organisation_id = ?", orgID)
	if f.Q != "" {
		w.add(`strpos(lower(g.name), lower(?)) > 0`, f.Q)
	}
	members := `(SELECT count(*) FROM group_members m JOIN users u ON u.id = m.user_id
		WHERE m.group_id = g.id AND u.status <> 'deleted')`
	perms := `(SELECT count(*) FROM group_permissions p WHERE p.group_id = g.id)`
	if f.Members != nil {
		op, ok := memberOps[f.Members.Op]
		if !ok {
			return nil, fmt.Errorf("member count: unknown comparison %q", f.Members.Op)
		}
		w.add(members+" "+op+" ?", f.Members.N)
	}
	if f.Permissions != nil {
		if *f.Permissions {
			w.add(perms + " > 0")
		} else {
			w.add(perms + " = 0")
		}
	}
	order := map[string]string{"members": members, "permissions": perms, "created": "g.created_at"}[f.Sort]
	if order == "" {
		order = "lower(g.name)"
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	rows, err := s.DB.Query(ctx, `SELECT `+groupColumns+` FROM groups g WHERE `+strings.Join(w.sql, " AND ")+
		` ORDER BY `+order+` `+dir+`, lower(g.name), g.id`, w.args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Group])
}

// Group in an organisation (ErrNotFound otherwise).
func (s *Store) Group(ctx context.Context, orgID, groupID string) (*Group, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+groupColumns+` FROM groups g WHERE g.organisation_id = $1 AND g.id = $2`,
		orgID, groupID)
	if err != nil {
		return nil, err
	}
	g, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Group])
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

func (s *Store) CreateGroup(ctx context.Context, orgID, name string) (*Group, error) {
	var id string
	if err := s.DB.QueryRow(ctx, `INSERT INTO groups (organisation_id, name) VALUES ($1, $2) RETURNING id`,
		orgID, name).Scan(&id); err != nil {
		return nil, err
	}
	return s.Group(ctx, orgID, id)
}

func (s *Store) RenameGroup(ctx context.Context, orgID, groupID, name string) error {
	_, err := s.DB.Exec(ctx, `UPDATE groups SET name = $3 WHERE organisation_id = $1 AND id = $2`, orgID, groupID, name)
	return err
}

// DeleteGroup deletes a group. App rules about it lose it; a rule that was
// only about this group goes too (with no conditions it would apply to
// everyone).
func (s *Store) DeleteGroup(ctx context.Context, orgID, groupID string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM app_rules WHERE organisation_id = $1 AND group_ids = ARRAY[$2::uuid]
		AND cardinality(user_ids) = 0 AND cardinality(ip_ranges) = 0`, orgID, groupID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE app_rules SET group_ids = array_remove(group_ids, $2::uuid)
		WHERE organisation_id = $1 AND $2::uuid = ANY(group_ids)`, orgID, groupID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM groups WHERE organisation_id = $1 AND id = $2`, orgID, groupID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GroupMembers(ctx context.Context, groupID string) ([]User, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+userColumns+` FROM users
		WHERE id IN (SELECT user_id FROM group_members WHERE group_id = $1) AND status <> 'deleted' ORDER BY name`, groupID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) {
		u, err := scanUser(r)
		if err != nil {
			return User{}, err
		}
		return *u, nil
	})
}

func (s *Store) AddGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		groupID, userID)
	return err
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	return err
}

// GroupIDsForUser: the groups someone is in.
func (s *Store) GroupIDsForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT group_id::text FROM group_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// GroupIDsInOrganisation: the groups everyone is in, by user ID.
func (s *Store) GroupIDsInOrganisation(ctx context.Context, orgID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT m.user_id::text, m.group_id::text FROM group_members m
		JOIN groups g ON g.id = m.group_id WHERE g.organisation_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	var user, group string
	_, err = pgx.ForEachRow(rows, []any{&user, &group}, func() error {
		out[user] = append(out[user], group)
		return nil
	})
	return out, err
}

// ── App access ───────────────────────────────────────────────────────────

// App access modes.
const (
	AppForced   = "forced"   // on, and people can't turn it off
	AppEnabled  = "enabled"  // on, and each person can turn it off
	AppDisabled = "disabled" // off, and people can't use it
)

// AppPolicy is the organisation's default for an app. (Per-group settings
// are rules now: app_rules.go.)
type AppPolicy struct {
	ClientID string `json:"clientId"`
	Mode     string `json:"mode"`
}

func (s *Store) AppPolicies(ctx context.Context, orgID string) ([]AppPolicy, error) {
	rows, err := s.DB.Query(ctx, `SELECT client_id, mode FROM app_policies
		WHERE organisation_id = $1 AND group_id IS NULL`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AppPolicy])
}

// SetAppPolicy sets the organisation's default for an app; mode "" removes it
// (back to Keston's own: forced for Keston's apps, otherwise up to each
// person).
func (s *Store) SetAppPolicy(ctx context.Context, orgID, clientID, mode string) error {
	if mode == "" {
		_, err := s.DB.Exec(ctx, `DELETE FROM app_policies WHERE organisation_id = $1
			AND group_id IS NULL AND client_id = $2`, orgID, clientID)
		return err
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO app_policies (organisation_id, group_id, client_id, mode)
		VALUES ($1, NULL, $2, $3)
		ON CONFLICT (organisation_id, coalesce(group_id, '00000000-0000-0000-0000-000000000000'), client_id)
		DO UPDATE SET mode = $3, updated_at = now()`, orgID, clientID, mode)
	return err
}

// EffectiveApps is someone's access to each app that has a setting (or is
// one of Keston's own): the first of the app's rules that matches them, else
// the organisation's default, else forced for Keston's own apps. Apps not in
// the map are up to them. The address is the one they're signing in from, for
// rules on IP addresses ("" when not known: those rules don't match).
func (s *Store) EffectiveApps(ctx context.Context, u *User) (map[string]string, error) {
	return s.EffectiveAppsFrom(ctx, u, "")
}

func (s *Store) EffectiveAppsFrom(ctx context.Context, u *User, ip string) (map[string]string, error) {
	out := map[string]string{}
	builtin, err := s.BuiltinClients(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range builtin {
		out[c.ID] = AppForced
	}
	policies, err := s.AppPolicies(ctx, u.OrganisationID)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		out[p.ClientID] = p.Mode
	}
	rules, err := s.AppRulesByApp(ctx, u.OrganisationID)
	if err != nil {
		return nil, err
	}
	if len(rules) > 0 {
		groups, err := s.GroupIDsForUser(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for id, list := range rules {
			if mode := ResolveAppMode("", list, u.ID, groups, ip); mode != "" {
				out[id] = mode
			}
		}
	}
	// No licence, no access to a Keston product (support accounts aside).
	if !u.IsSupport() {
		have, err := s.Licences(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range builtin {
			if !slices.Contains(have, c.ID) {
				out[c.ID] = AppDisabled
			}
		}
	}
	return out, nil
}
