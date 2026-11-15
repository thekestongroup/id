package store

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ── Admin roles ───────────────────────────────────────────────────────────
//
// Built-in sets of Keston Admin permissions, given straight to a user (like
// Microsoft's admin roles). Global admin is users.role (everything, and a
// few things only global admins do); these are the rest. Someone's
// permissions are their roles' plus their groups'.

type AdminRole struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// AdminRoles, in the order Keston Admin shows them (after Global admin).
var AdminRoles = []AdminRole{
	{"user_admin", "User admin", "Adds, edits and deletes users, resets their passwords and MFA, and manages groups and licences.",
		[]string{PermViewUsers, PermCreateUsers, PermEditUsers, PermResetPassword, PermResetMFA, PermAccessPass,
			PermUserStatus, PermDeleteUsers, PermLicences, PermGroups}},
	{"helpdesk_admin", "Helpdesk admin", "Resets passwords and MFA, issues access passes, and blocks or allows sign-in.",
		[]string{PermViewUsers, PermResetPassword, PermResetMFA, PermAccessPass, PermUserStatus}},
	{"groups_admin", "Groups admin", "Creates and manages groups, and who's in them.",
		[]string{PermViewUsers, PermGroups}},
	{"licence_admin", "Licence admin", "Assigns licences for Keston's products.",
		[]string{PermViewUsers, PermLicences}},
	{"apps_admin", "Apps admin", "Chooses which apps users have, and manages your own apps.",
		[]string{PermApps}},
	{"security_admin", "Security admin", "Sets the password policy and MFA, turns off users' MFA, and sees the logs.",
		[]string{PermViewUsers, PermResetMFA, PermPolicy, PermReports}},
	{"reports_reader", "Reports reader", "Sees the logs: what admins did, and every sign-in.",
		[]string{PermReports}},
}

// RoleByID: one of AdminRoles, or nil.
func RoleByID(id string) *AdminRole {
	for i := range AdminRoles {
		if AdminRoles[i].ID == id {
			return &AdminRoles[i]
		}
	}
	return nil
}

// RolePermissions: every permission these roles give.
func RolePermissions(roles []string) []string {
	out := []string{}
	for _, id := range roles {
		if r := RoleByID(id); r != nil {
			for _, p := range r.Permissions {
				if !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// RolesOf: someone's admin roles, in catalogue order.
func (s *Store) RolesOf(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT role FROM user_roles WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range AdminRoles {
		if slices.Contains(have, r.ID) {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

// RolesInOrganisation: everyone's admin roles, by user ID.
func (s *Store) RolesInOrganisation(ctx context.Context, orgID string) (map[string][]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT r.user_id::text, r.role FROM user_roles r
		JOIN users u ON u.id = r.user_id WHERE u.organisation_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	var userID, role string
	_, err = pgx.ForEachRow(rows, []any{&userID, &role}, func() error {
		out[userID] = append(out[userID], role)
		return nil
	})
	return out, err
}

// SetRoles makes someone's admin roles exactly these (unknown ones are
// ErrNotFound). It returns what was added and removed.
func (s *Store) SetRoles(ctx context.Context, userID string, roles []string) (added, removed []string, err error) {
	for _, r := range roles {
		if RoleByID(r) == nil {
			return nil, nil, ErrNotFound
		}
	}
	before, err := s.RolesOf(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range roles {
		if !slices.Contains(before, r) && !slices.Contains(added, r) {
			added = append(added, r)
		}
	}
	for _, r := range before {
		if !slices.Contains(roles, r) {
			removed = append(removed, r)
		}
	}
	if _, err := s.DB.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role = ANY($2)`, userID, removed); err != nil {
		return nil, nil, err
	}
	for _, r := range added {
		if _, err := s.DB.Exec(ctx, `INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			userID, r); err != nil {
			return nil, nil, err
		}
	}
	return added, removed, nil
}
