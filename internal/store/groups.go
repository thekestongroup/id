package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Groups ───────────────────────────────────────────────────────────────

type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	MemberCount int       `json:"memberCount"`
	CreatedAt   time.Time `json:"createdAt"`
}

const groupColumns = `g.id, g.name, (SELECT count(*) FROM group_members m WHERE m.group_id = g.id), g.created_at`

func (s *Store) Groups(ctx context.Context, orgID string) ([]Group, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+groupColumns+` FROM groups g WHERE g.organisation_id = $1
		ORDER BY lower(g.name)`, orgID)
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

func (s *Store) DeleteGroup(ctx context.Context, orgID, groupID string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM groups WHERE organisation_id = $1 AND id = $2`, orgID, groupID)
	return err
}

func (s *Store) GroupMembers(ctx context.Context, groupID string) ([]User, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+userColumns+` FROM users
		WHERE id IN (SELECT user_id FROM group_members WHERE group_id = $1) ORDER BY name`, groupID)
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

// ── App access ───────────────────────────────────────────────────────────

// App access modes.
const (
	AppForced   = "forced"   // on, and people can't turn it off
	AppEnabled  = "enabled"  // on, and each person can turn it off
	AppDisabled = "disabled" // off, and people can't use it
)

// AppPolicy is one setting: the organisation's default (GroupID nil) or a
// group's.
type AppPolicy struct {
	GroupID  *string `json:"groupId"`
	ClientID string  `json:"clientId"`
	Mode     string  `json:"mode"`
}

func (s *Store) AppPolicies(ctx context.Context, orgID string) ([]AppPolicy, error) {
	rows, err := s.DB.Query(ctx, `SELECT group_id::text, client_id, mode FROM app_policies WHERE organisation_id = $1`,
		orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AppPolicy])
}

// SetAppPolicy sets the default (groupID nil) or a group's mode for an app;
// mode "" removes the setting (back to the default, or Keston's own).
func (s *Store) SetAppPolicy(ctx context.Context, orgID string, groupID *string, clientID, mode string) error {
	if mode == "" {
		_, err := s.DB.Exec(ctx, `DELETE FROM app_policies WHERE organisation_id = $1
			AND group_id IS NOT DISTINCT FROM $2::uuid AND client_id = $3`, orgID, groupID, clientID)
		return err
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO app_policies (organisation_id, group_id, client_id, mode)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (organisation_id, coalesce(group_id, '00000000-0000-0000-0000-000000000000'), client_id)
		DO UPDATE SET mode = $4, updated_at = now()`, orgID, groupID, clientID, mode)
	return err
}

// rank: when someone's groups disagree, Disabled wins, then Forced, then
// Enabled (blocking an app is the safe way round).
var rank = map[string]int{AppDisabled: 3, AppForced: 2, AppEnabled: 1}

// EffectiveApps is someone's access to each app that has a setting (or is
// one of Keston's own): their groups' settings where any apply, otherwise
// the organisation's default, otherwise forced for Keston's own apps. Apps
// not in the map are up to them.
func (s *Store) EffectiveApps(ctx context.Context, u *User) (map[string]string, error) {
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
	groups, err := s.GroupIDsForUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	in := map[string]bool{}
	for _, g := range groups {
		in[g] = true
	}
	fromGroups := map[string]string{}
	for _, p := range policies {
		switch {
		case p.GroupID == nil:
			out[p.ClientID] = p.Mode
		case in[*p.GroupID] && rank[p.Mode] > rank[fromGroups[p.ClientID]]:
			fromGroups[p.ClientID] = p.Mode
		}
	}
	for id, mode := range fromGroups {
		out[id] = mode
	}
	return out, nil
}
