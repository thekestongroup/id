package store

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ── Keston Admin permissions ─────────────────────────────────────────────
//
// Given to groups: everyone in the group can do these in Keston Admin, in
// their own organisation. Global admins can do all of them (and a few
// things only they can: making global admins, support access, deleting
// the organisation).
//
// "Lower" users only: someone can change a user only if every permission
// that user has is one they have too (and only global admins can change
// global admins). Giving permissions works the same way: a group's
// permissions, and who's in it, can only be changed by someone who has
// every one of them.

type Permission struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

const (
	PermViewUsers     = "users.view"
	PermCreateUsers   = "users.create"
	PermEditUsers     = "users.edit"
	PermResetPassword = "users.reset_password"
	PermResetMFA      = "users.mfa"
	PermUserStatus    = "users.status"
	PermGroups        = "groups.manage"
	PermAssign        = "permissions.assign"
	PermApps          = "apps.manage"
	PermPolicy        = "policy.manage"
	PermSettings      = "settings.manage"
	PermReports       = "reports.view"
)

// Permissions, in the order Keston Admin shows them.
var Permissions = []Permission{
	{PermViewUsers, "See users", "The list of users and their details."},
	{PermCreateUsers, "Add users", "New users, as members (not global admins)."},
	{PermEditUsers, "Edit users", "Names, usernames and profile pictures."},
	{PermResetPassword, "Reset passwords", "Set a new password, which also unlocks them and signs them out."},
	{PermResetMFA, "Turn off MFA", "For someone who's lost their authenticator."},
	{PermUserStatus, "Disable and enable users", "A disabled user can't sign in."},
	{PermGroups, "Manage groups", "Create, rename and delete groups, and choose who's in them."},
	{PermAssign, "Give permissions", "Set a group's permissions, and who's in it, up to their own permissions."},
	{PermApps, "Set app access", "Which apps users have (Apps)."},
	{PermPolicy, "Set the password policy", "The rules for new passwords."},
	{PermSettings, "Change settings", "What users can change in their own profiles."},
	{PermReports, "See logs", "What admins did, and every sign-in, for the last year."},
}

// needsView: permissions that act on users, which need seeing them too.
var needsView = []string{PermCreateUsers, PermEditUsers, PermResetPassword, PermResetMFA, PermUserStatus, PermGroups,
	PermAssign}

// CleanPermissions keeps known permissions only, sorted, adding "See users"
// where another one needs it.
func CleanPermissions(in []string) []string {
	out := []string{}
	for _, p := range Permissions {
		if slices.Contains(in, p.ID) {
			out = append(out, p.ID)
		}
	}
	for _, p := range needsView {
		if slices.Contains(out, p) && !slices.Contains(out, PermViewUsers) {
			out = append(out, PermViewUsers)
		}
	}
	slices.Sort(out)
	return out
}

// Perms is a set of permissions.
type Perms map[string]bool

func (p Perms) Has(id string) bool { return p[id] }

// Covers: every one of these is in p.
func (p Perms) Covers(ids []string) bool {
	for _, id := range ids {
		if !p[id] {
			return false
		}
	}
	return true
}

func (p Perms) List() []string {
	out := []string{}
	for id := range p {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// PermissionsOf: what someone can do in Keston Admin, in their own
// organisation: everything for a global admin, otherwise what their
// groups give them.
func (s *Store) PermissionsOf(ctx context.Context, u *User) (Perms, error) {
	out := Perms{}
	if u.Role == "global_admin" {
		for _, p := range Permissions {
			out[p.ID] = true
		}
		return out, nil
	}
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT p.permission FROM group_permissions p
		JOIN group_members m ON m.group_id = p.group_id WHERE m.user_id = $1`, u.ID)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// SetGroupPermissions replaces a group's permissions.
func (s *Store) SetGroupPermissions(ctx context.Context, groupID string, perms []string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM group_permissions WHERE group_id = $1`, groupID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO group_permissions (group_id, permission)
		SELECT $1, unnest($2::text[])`, groupID, perms); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GroupsOf: the groups someone is in.
func (s *Store) GroupsOf(ctx context.Context, userID string) ([]Group, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+groupColumns+` FROM groups g
		WHERE g.id IN (SELECT group_id FROM group_members WHERE user_id = $1) ORDER BY lower(g.name)`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Group])
}

// PermissionsInOrganisation: every user's permissions there (global admins
// get them all), for checking a whole list at once.
func (s *Store) PermissionsInOrganisation(ctx context.Context, orgID string) (map[string]Perms, error) {
	rows, err := s.DB.Query(ctx, `SELECT m.user_id::text, p.permission FROM group_permissions p
		JOIN group_members m ON m.group_id = p.group_id
		JOIN groups g ON g.id = p.group_id WHERE g.organisation_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	out := map[string]Perms{}
	var userID, perm string
	_, err = pgx.ForEachRow(rows, []any{&userID, &perm}, func() error {
		if out[userID] == nil {
			out[userID] = Perms{}
		}
		out[userID][perm] = true
		return nil
	})
	return out, err
}
