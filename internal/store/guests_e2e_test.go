//go:build e2e

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
)

// Guest memberships and account moves, at the store level: who can be
// invited, what counts as a membership, and what a guest can and can't have.
func TestGuestsAndMoves(t *testing.T) {
	url := os.Getenv("KESTON_ID_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KESTON_ID_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	st := New(pool, nil)
	domain := func() string { return "g" + strings.ToLower(secret.Token()[:10]) + ".test" }
	mk := func(name string) (*Organisation, *User) {
		d := domain()
		o, a, err := st.CreateOrganisation(ctx, name, d, NewUser{Email: "admin@" + d, Name: name + " admin", PasswordHash: "x"})
		if err != nil {
			t.Fatal(err)
		}
		return o, a
	}
	guestOrg, gadmin := mk("Guest org")
	home, hadmin := mk("Home org")
	bob, err := st.CreateUser(ctx, st.DB, NewUser{OrganisationID: home.ID, Email: "bob@" + home.Domain, Name: "Bob", PasswordHash: "x"})
	if err != nil {
		t.Fatal(err)
	}

	// Off by default: undeliverable, the same as for an unknown address.
	if _, err := st.InviteGuest(ctx, guestOrg, bob.Email, gadmin); !errors.Is(err, ErrGuestUndeliverable) {
		t.Errorf("setting off: %v", err)
	}
	if _, err := st.InviteGuest(ctx, guestOrg, "nobody@"+home.Domain, gadmin); !errors.Is(err, ErrGuestUndeliverable) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := st.InviteGuest(ctx, guestOrg, hadmin.Email, gadmin); !errors.Is(err, ErrGuestUndeliverable) {
		t.Errorf("another organisation that hasn't allowed guests: %v", err)
	}
	_ = st.SetAllowGuests(ctx, home.ID, true)
	if _, err := st.InviteGuest(ctx, home, bob.Email, hadmin); !errors.Is(err, ErrGuestSameOrganisation) {
		t.Errorf("own organisation: %v", err)
	}
	// Disabled accounts can't be invited.
	_ = st.SetUserStatus(ctx, bob.ID, "disabled")
	if _, err := st.InviteGuest(ctx, guestOrg, bob.Email, gadmin); !errors.Is(err, ErrGuestUndeliverable) {
		t.Errorf("disabled: %v", err)
	}
	_ = st.SetUserStatus(ctx, bob.ID, "active")

	g, err := st.InviteGuest(ctx, guestOrg, bob.Email, gadmin)
	if err != nil || g.Status != "pending" || g.HomeOrganisationID != home.ID {
		t.Fatalf("invite: %+v %v", g, err)
	}
	if _, err := st.InviteGuest(ctx, guestOrg, bob.Email, gadmin); !errors.Is(err, ErrGuestExists) {
		t.Errorf("twice: %v", err)
	}
	// Pending isn't a membership.
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("pending counted: %v", err)
	}
	// Only the invitee answers.
	if _, err := st.RespondToInvitation(ctx, g.ID, hadmin.ID, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("someone else answering: %v", err)
	}
	if _, err := st.RespondToInvitation(ctx, g.ID, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RespondToInvitation(ctx, g.ID, bob.ID, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("answering twice: %v", err)
	}
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); err != nil {
		t.Errorf("accepted guest: %v", err)
	}

	// Permissions: only in the guest organisation, from its groups and roles.
	grp, _ := st.CreateGroup(ctx, guestOrg.ID, "Helpers")
	_ = st.SetGroupPermissions(ctx, grp.ID, []string{PermViewUsers, PermReports})
	_ = st.AddGroupMember(ctx, grp.ID, bob.ID)
	cur, _ := st.GuestByID(ctx, g.ID)
	if _, _, err := st.SetGuestRoles(ctx, cur, []string{"helpdesk_admin"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.SetGuestRoles(ctx, cur, []string{"nonsense"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown role: %v", err)
	}
	inGuest, _ := st.PermissionsIn(ctx, bob, guestOrg.ID)
	if !inGuest.Has(PermReports) || !inGuest.Has(PermResetPassword) || inGuest.Has(PermDeleteUsers) {
		t.Errorf("guest permissions: %v", inGuest.List())
	}
	if p, _ := st.PermissionsIn(ctx, bob, home.ID); len(p) != 0 {
		t.Errorf("home permissions: %v", p.List())
	}
	if p, _ := st.PermissionsOf(ctx, bob); len(p) != 0 {
		t.Errorf("PermissionsOf picked up the guest organisation's groups: %v", p.List())
	}
	if p, _ := st.PermissionsIn(ctx, bob, "00000000-0000-0000-0000-000000000000"); len(p) != 0 {
		t.Errorf("unknown organisation: %v", p.List())
	}
	// A home global admin is only a member in the guest organisation.
	_ = st.SetAllowGuests(ctx, home.ID, true)
	adminGuest, err := st.InviteGuest(ctx, guestOrg, hadmin.Email, gadmin)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = st.RespondToInvitation(ctx, adminGuest.ID, hadmin.ID, true)
	if p, _ := st.PermissionsIn(ctx, hadmin, guestOrg.ID); len(p) != 0 {
		t.Errorf("a home global admin got permissions as a guest: %v", p.List())
	}

	// On hold while the home organisation doesn't allow guests; back when it does.
	_ = st.SetAllowGuests(ctx, home.ID, false)
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("membership counted while off: %v", err)
	}
	if p, _ := st.PermissionsIn(ctx, bob, guestOrg.ID); len(p) != 0 {
		t.Errorf("permissions while off: %v", p.List())
	}
	if list, _ := st.GuestsInOrganisation(ctx, guestOrg.ID); len(list) != 2 || list[0].Active || list[1].Active {
		t.Errorf("listed as active while off: %+v", list)
	}
	_ = st.SetAllowGuests(ctx, home.ID, true)
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); err != nil {
		t.Errorf("not restored: %v", err)
	}
	// A disabled account isn't a guest anywhere.
	_ = st.SetUserStatus(ctx, bob.ID, "disabled")
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("disabled guest: %v", err)
	}
	_ = st.SetUserStatus(ctx, bob.ID, "active")

	mine, _ := st.MyOrganisations(ctx, bob)
	if len(mine) != 2 || !mine[0].Home || mine[0].ID != home.ID || mine[1].ID != guestOrg.ID {
		t.Errorf("my organisations: %+v", mine)
	}

	// Ending it removes the groups and roles, but not the account.
	if err := st.EndGuest(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GuestIn(ctx, bob.ID, guestOrg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed guest: %v", err)
	}
	if ids, _ := st.GroupIDsInOrganisation(ctx, guestOrg.ID); len(ids[bob.ID]) != 0 {
		t.Errorf("groups remain: %v", ids[bob.ID])
	}
	after, _ := st.GuestByID(ctx, g.ID)
	if after.Status != "removed" || len(after.AdminRoles) != 0 {
		t.Errorf("after removal: %+v", after)
	}
	if u, _ := st.UserByID(ctx, bob.ID); u.Status != "active" || u.OrganisationID != home.ID {
		t.Errorf("the account changed: %+v", u)
	}
	// Re-invited from scratch: no roles, a fresh pop-up.
	_ = st.MarkPromptSeen(ctx, bob.ID, "guest_invitation", g.ID)
	again, err := st.InviteGuest(ctx, guestOrg, bob.Email, gadmin)
	if err != nil || again.ID != g.ID || again.Status != "pending" || len(again.AdminRoles) != 0 {
		t.Fatalf("re-invite: %+v %v", again, err)
	}
	if seen, _ := st.PromptsSeen(ctx, bob.ID, "guest_invitation"); seen[g.ID] {
		t.Error("the pop-up for a new invitation was already seen")
	}

	// Moving: the email changes domain, the account becomes a plain member.
	carol, _ := st.CreateUser(ctx, st.DB, NewUser{OrganisationID: home.ID, Email: "carol@" + home.Domain, Name: "Carol", Role: "global_admin", PasswordHash: "x"})
	m, err := st.RequestMove(ctx, carol, guestOrg, hadmin)
	if err != nil || m.NewEmail != "carol@"+guestOrg.Domain {
		t.Fatalf("request: %+v %v", m, err)
	}
	if _, err := st.RequestMove(ctx, carol, guestOrg, hadmin); !errors.Is(err, ErrPending) {
		t.Errorf("second request: %v", err)
	}
	// Only the receiving organisation decides.
	if _, ok, _ := st.DecideMove(ctx, m.ID, home.ID, true, hadmin); ok {
		t.Error("the asking organisation accepted")
	}
	if _, ok, err := st.DecideMove(ctx, m.ID, guestOrg.ID, true, gadmin); !ok || err != nil {
		t.Fatalf("accept: %v %v", ok, err)
	}
	moved, _ := st.UserByID(ctx, carol.ID)
	if moved.OrganisationID != guestOrg.ID || moved.Email != "carol@"+guestOrg.Domain || moved.Role != "member" {
		t.Errorf("moved: %+v", moved)
	}
	// The original organisation can't move its only global admin.
	if _, err := st.RequestMove(ctx, hadmin, guestOrg, hadmin); !errors.Is(err, ErrMoveLastAdmin) {
		t.Errorf("last admin: %v", err)
	}
	if _, err := st.RequestMove(ctx, moved, guestOrg, gadmin); !errors.Is(err, ErrMoveOrganisation) {
		t.Errorf("same organisation: %v", err)
	}
}
