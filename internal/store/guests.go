package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── Guests ───────────────────────────────────────────────────────────────
//
// Someone's home organisation (users.organisation_id) owns their account:
// their email, password, MFA, deletion, and every app, token and sign-in.
// An organisation can also invite people from other organisations to be
// guests in Keston Admin: as a guest they're a member of that organisation
// there, with the groups and admin roles it gives them (none by default,
// which means no access to Keston Admin there), and nowhere else.
//
// A guest membership only counts while the person's home organisation
// still allows its people to be guests (organisations.allow_guests), and
// the person can still sign in.

var (
	// The invitation can't be delivered: the address isn't a person who can
	// be invited, or their home organisation doesn't allow guests. One error
	// for both, so inviters learn nothing more than they have to.
	ErrGuestUndeliverable = errors.New("guest invitation can't be delivered")
	// They already belong to the organisation.
	ErrGuestSameOrganisation = errors.New("already a member")
	// There's already a pending invitation or an accepted membership.
	ErrGuestExists = errors.New("already a guest or invited")
)

// Guest is a guest membership: an invitation, or a guest in an organisation.
type Guest struct {
	ID                   string `json:"id"`
	OrganisationID       string `json:"organisationId"`
	OrganisationName     string `json:"organisationName"`
	OrganisationDomain   string `json:"organisationDomain"`
	UserID               string `json:"userId"`
	UserName             string `json:"name"`
	UserEmail            string `json:"email"`
	HomeOrganisationID   string `json:"homeOrganisationId"`
	HomeOrganisationName string `json:"homeOrganisationName"`
	// Admin roles (AdminRoles) this organisation gave them, for Keston Admin there.
	AdminRoles []string `json:"roles"`
	// pending, accepted, declined or removed.
	Status        string     `json:"status"`
	InvitedBy     *string    `json:"invitedBy"`
	InvitedByName string     `json:"invitedByName"`
	CreatedAt     time.Time  `json:"createdAt"`
	RespondedAt   *time.Time `json:"respondedAt,omitempty"`
	// Their home organisation allows guests right now; if not, the
	// membership is on hold (it counts for nothing).
	Active bool `json:"active"`
}

const guestFrom = ` FROM guest_memberships g
	JOIN organisations go ON go.id = g.organisation_id
	JOIN users u ON u.id = g.user_id
	JOIN organisations ho ON ho.id = u.organisation_id`

const guestColumns = `g.id::text, g.organisation_id::text, go.name, go.domain, g.user_id::text, u.name, u.email,
	u.organisation_id::text, ho.name, g.admin_roles, g.status, g.invited_by::text, g.invited_by_name, g.created_at,
	g.responded_at, (ho.allow_guests AND ho.verified_at IS NOT NULL)`

func scanGuest(row pgx.CollectableRow) (Guest, error) {
	var g Guest
	err := row.Scan(&g.ID, &g.OrganisationID, &g.OrganisationName, &g.OrganisationDomain, &g.UserID, &g.UserName,
		&g.UserEmail, &g.HomeOrganisationID, &g.HomeOrganisationName, &g.AdminRoles, &g.Status, &g.InvitedBy,
		&g.InvitedByName, &g.CreatedAt, &g.RespondedAt, &g.Active)
	if g.AdminRoles == nil {
		g.AdminRoles = []string{}
	}
	return g, err
}

func (s *Store) guests(ctx context.Context, where string, args ...any) ([]Guest, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+guestColumns+guestFrom+` WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanGuest)
}

// GuestByID: one membership, whatever its status.
func (s *Store) GuestByID(ctx context.Context, id string) (*Guest, error) {
	if !IsUUID(id) {
		return nil, ErrNotFound
	}
	list, err := s.guests(ctx, `g.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// SetAllowGuests: whether the organisation's people may be guests elsewhere.
func (s *Store) SetAllowGuests(ctx context.Context, orgID string, on bool) error {
	_, err := s.DB.Exec(ctx, `UPDATE organisations SET allow_guests = $2 WHERE id = $1`, orgID, on)
	return err
}

// InviteGuest invites the person with this email to be a guest in org. It
// only goes through if they're an ordinary account in another organisation,
// and that organisation allows guests (ErrGuestUndeliverable otherwise).
func (s *Store) InviteGuest(ctx context.Context, org *Organisation, email string, by *User) (*Guest, error) {
	invitee, err := s.UserByEmail(ctx, strings.TrimSpace(email))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrGuestUndeliverable
	}
	if err != nil {
		return nil, err
	}
	if invitee.OrganisationID == org.ID {
		return nil, ErrGuestSameOrganisation
	}
	home, err := s.OrganisationByID(ctx, invitee.OrganisationID)
	if err != nil {
		return nil, err
	}
	if invitee.IsSupport() || invitee.Status != "active" || !home.AllowGuests || !home.Verified {
		return nil, ErrGuestUndeliverable
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var id, status string
	err = tx.QueryRow(ctx, `SELECT id::text, status FROM guest_memberships
		WHERE organisation_id = $1 AND user_id = $2 FOR UPDATE`, org.ID, invitee.ID).Scan(&id, &status)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `INSERT INTO guest_memberships (organisation_id, user_id, invited_by, invited_by_name)
			VALUES ($1, $2, $3, $4) RETURNING id::text`, org.ID, invitee.ID, by.ID, by.Name).Scan(&id)
	case err != nil:
		return nil, err
	case status == "pending" || status == "accepted":
		return nil, ErrGuestExists
	default:
		_, err = tx.Exec(ctx, `UPDATE guest_memberships SET status = 'pending', admin_roles = '{}', invited_by = $2,
			invited_by_name = $3, responded_at = NULL, created_at = now(), updated_at = now() WHERE id = $1`,
			id, by.ID, by.Name)
		if err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM prompt_seen WHERE kind = 'guest_invitation' AND ref_id = $1`, id)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GuestByID(ctx, id)
}

// GuestsInOrganisation: its pending invitations and accepted guests.
func (s *Store) GuestsInOrganisation(ctx context.Context, orgID string) ([]Guest, error) {
	return s.guests(ctx, `g.organisation_id = $1 AND g.status IN ('pending', 'accepted') AND u.status <> 'deleted'
		ORDER BY lower(u.name)`, orgID)
}

// InvitationsFor: invitations waiting for this person (only while their
// home organisation allows guests).
func (s *Store) InvitationsFor(ctx context.Context, userID string) ([]Guest, error) {
	return s.guests(ctx, `g.user_id = $1 AND g.status = 'pending' AND ho.allow_guests AND ho.verified_at IS NOT NULL
		ORDER BY g.created_at DESC`, userID)
}

// GuestMembershipsOf: the organisations someone is a guest in right now.
func (s *Store) GuestMembershipsOf(ctx context.Context, userID string) ([]Guest, error) {
	return s.guests(ctx, `g.user_id = $1 AND g.status = 'accepted' AND ho.allow_guests AND ho.verified_at IS NOT NULL
		AND go.verified_at IS NOT NULL ORDER BY lower(go.name)`, userID)
}

// GuestIn: their accepted, active membership in this organisation, or
// ErrNotFound (a person's own organisation never counts: they're a member).
func (s *Store) GuestIn(ctx context.Context, userID, orgID string) (*Guest, error) {
	if !IsUUID(userID) || !IsUUID(orgID) {
		return nil, ErrNotFound
	}
	list, err := s.guests(ctx, `g.user_id = $1 AND g.organisation_id = $2 AND g.status = 'accepted'
		AND ho.allow_guests AND ho.verified_at IS NOT NULL AND u.status = 'active' AND u.organisation_id <> g.organisation_id`,
		userID, orgID)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	return &list[0], nil
}

// RespondToInvitation: accept or decline their own pending invitation
// (ErrNotFound if it isn't theirs, isn't pending, or their organisation no
// longer allows guests).
func (s *Store) RespondToInvitation(ctx context.Context, id, userID string, accept bool) (*Guest, error) {
	status := "declined"
	if accept {
		status = "accepted"
	}
	if !IsUUID(id) {
		return nil, ErrNotFound
	}
	tag, err := s.DB.Exec(ctx, `UPDATE guest_memberships g SET status = $3, responded_at = now(), updated_at = now()
		WHERE g.id = $1 AND g.user_id = $2 AND g.status = 'pending'
		AND EXISTS (SELECT 1 FROM users u JOIN organisations ho ON ho.id = u.organisation_id
			WHERE u.id = g.user_id AND ho.allow_guests AND ho.verified_at IS NOT NULL)`, id, userID, status)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GuestByID(ctx, id)
}

// EndGuest removes a membership (or withdraws an invitation): the organisation
// can't be worked in any more, and its groups and roles go with it.
func (s *Store) EndGuest(ctx context.Context, g *Guest) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE guest_memberships SET status = 'removed', admin_roles = '{}',
		responded_at = now(), updated_at = now() WHERE id = $1 AND status IN ('pending', 'accepted')`, g.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM group_members WHERE user_id = $1
		AND group_id IN (SELECT id FROM groups WHERE organisation_id = $2)`, g.UserID, g.OrganisationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetGuestRoles makes a guest's admin roles in the organisation exactly
// these. It returns what was added and removed.
func (s *Store) SetGuestRoles(ctx context.Context, g *Guest, roles []string) (added, removed []string, err error) {
	for _, r := range roles {
		if RoleByID(r) == nil {
			return nil, nil, ErrNotFound
		}
	}
	// Catalogue order, no repeats.
	clean := []string{}
	for _, r := range AdminRoles {
		if slices.Contains(roles, r.ID) {
			clean = append(clean, r.ID)
		}
	}
	for _, r := range clean {
		if !slices.Contains(g.AdminRoles, r) {
			added = append(added, r)
		}
	}
	for _, r := range g.AdminRoles {
		if !slices.Contains(clean, r) {
			removed = append(removed, r)
		}
	}
	_, err = s.DB.Exec(ctx, `UPDATE guest_memberships SET admin_roles = $2, updated_at = now()
		WHERE id = $1 AND status = 'accepted'`, g.ID, clean)
	return added, removed, err
}

// PermissionsIn: what someone can do in Keston Admin in this organisation:
// their own permissions in their home organisation, or as an accepted
// guest what this organisation's groups and roles give them. Nothing in
// any other organisation.
func (s *Store) PermissionsIn(ctx context.Context, u *User, orgID string) (Perms, error) {
	if u.OrganisationID == orgID {
		return s.PermissionsOf(ctx, u)
	}
	g, err := s.GuestIn(ctx, u.ID, orgID)
	if errors.Is(err, ErrNotFound) {
		return Perms{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := Perms{}
	ids, err := s.groupPermissions(ctx, u.ID, orgID)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		out[id] = true
	}
	for _, id := range RolePermissions(g.AdminRoles) {
		out[id] = true
	}
	return out, nil
}

// IsGuestIn: the person is an accepted, active guest in the organisation.
func (s *Store) IsGuestIn(ctx context.Context, userID, orgID string) bool {
	_, err := s.GuestIn(ctx, userID, orgID)
	return err == nil
}

// MyOrganisation is an organisation someone can open in Keston Admin.
type MyOrganisation struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	// Their home organisation, or one they're a guest in.
	Home bool `json:"home"`
	// For a guest: the membership (to leave it).
	GuestID string `json:"guestId,omitempty"`
}

// MyOrganisations: their home organisation first, then the ones they're
// a guest in.
func (s *Store) MyOrganisations(ctx context.Context, u *User) ([]MyOrganisation, error) {
	home, err := s.OrganisationByID(ctx, u.OrganisationID)
	if err != nil {
		return nil, err
	}
	out := []MyOrganisation{{ID: home.ID, Name: home.Name, Domain: home.Domain, Home: true}}
	list, err := s.GuestMembershipsOf(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, g := range list {
		out = append(out, MyOrganisation{ID: g.OrganisationID, Name: g.OrganisationName, Domain: g.OrganisationDomain, GuestID: g.ID})
	}
	return out, nil
}

// ── One-time pop-ups ─────────────────────────────────────────────────────

// MarkPromptSeen: the pop-up for this invitation or request has been shown.
func (s *Store) MarkPromptSeen(ctx context.Context, userID, kind, refID string) error {
	if !IsUUID(refID) {
		return nil
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO prompt_seen (user_id, kind, ref_id) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, userID, kind, refID)
	return err
}

// PromptsSeen: the IDs of a kind of prompt they've already seen.
func (s *Store) PromptsSeen(ctx context.Context, userID, kind string) (map[string]bool, error) {
	rows, err := s.DB.Query(ctx, `SELECT ref_id::text FROM prompt_seen WHERE user_id = $1 AND kind = $2`, userID, kind)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out, err
}
