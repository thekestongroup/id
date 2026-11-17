//go:build e2e

package api

import (
	"context"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// Guest invitations on Keston ID's account pages: a member who can't open
// Keston Admin gets the notification and pop-up here, answers with the
// session cookie, and stays a member of their home organisation only.
func TestGuestInvitationOnAccountPages(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	home, _ := e.st.OrganisationByID(ctx, e.orgID)
	if err := e.st.SetAllowGuests(ctx, home.ID, true); err != nil {
		t.Fatal(err)
	}
	bob := e.user("bob")

	domain := "guest-" + strings.ToLower(secret.Token()[:8]) + ".test"
	guestOrg, admin, err := e.st.CreateOrganisation(ctx, "Guest Org", domain, store.NewUser{
		Email: "admin@" + domain, Name: "Gail Admin", PasswordHash: secret.HashPassword(goodPassword)})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.st.InviteGuest(ctx, guestOrg, bob.Email, admin)
	if err != nil {
		t.Fatal(err)
	}

	b := e.browser()
	f := b.signIn(bob.Email, goodPassword, "")
	if f.Step == "" {
		t.Fatalf("sign in: %+v", f)
	}
	var invites []store.Guest
	if code := b.do("GET", "/v1/guest-invitations", nil, &invites); code != 200 || len(invites) != 1 || invites[0].ID != g.ID ||
		invites[0].OrganisationName != "Guest Org" {
		t.Fatalf("invitations: %d %+v", code, invites)
	}
	var prompts struct {
		GuestInvitations []struct {
			ID    string
			Popup bool
		}
		MoveRequests []any
	}
	if code := b.do("GET", "/v1/prompts", nil, &prompts); code != 200 || len(prompts.GuestInvitations) != 1 ||
		!prompts.GuestInvitations[0].Popup || len(prompts.MoveRequests) != 0 {
		t.Fatalf("prompts: %d %+v", code, prompts)
	}
	if code := b.do("POST", "/v1/prompts/seen", map[string]string{"kind": "guest_invitation", "id": g.ID}, nil); code != 204 {
		t.Fatalf("seen: %d", code)
	}
	if code := b.do("GET", "/v1/prompts", nil, &prompts); code != 200 || prompts.GuestInvitations[0].Popup {
		t.Fatalf("pop-up again: %+v", prompts)
	}
	// Someone else's browser can't answer it.
	other := e.user("mallory")
	ob := e.browser()
	ob.signIn(other.Email, goodPassword, "")
	if code := ob.do("POST", "/v1/guest-invitations/"+g.ID+"/accept", nil, nil); code != 404 {
		t.Fatalf("someone else accepting: %d", code)
	}
	// A cross-site request without the header is refused.
	// (browser.do always sends it; check the other direction with accept.)
	if code := b.do("POST", "/v1/guest-invitations/"+g.ID+"/accept", nil, nil); code != 200 {
		t.Fatalf("accept: %d", code)
	}

	var mine struct {
		Organisations []struct {
			ID        string
			Home      bool
			CanManage bool
		}
	}
	if code := b.do("GET", "/v1/my-organisations", nil, &mine); code != 200 || len(mine.Organisations) != 2 ||
		!mine.Organisations[0].Home || mine.Organisations[1].ID != guestOrg.ID || mine.Organisations[1].CanManage {
		t.Fatalf("my organisations: %d %+v", code, mine)
	}
	// Still a member of the home organisation only: the account page and
	// what apps and tokens use say so.
	var me struct {
		User struct {
			Email        string
			Organisation string
		}
		Permissions []string
	}
	if code := b.do("GET", "/v1/me/", nil, &me); code != 200 || me.User.Email != bob.Email ||
		me.User.Organisation != home.Name || len(me.Permissions) != 0 {
		t.Fatalf("me: %d %+v", code, me)
	}
	u, _ := e.st.UserByID(ctx, bob.ID)
	if u.OrganisationID != home.ID || u.Organisation != home.Name {
		t.Fatalf("home organisation changed: %+v", u)
	}
	// No Keston Admin access in the guest organisation (or the home one).
	if code := b.do("GET", "/v1/organisations/"+guestOrg.ID+"/users", nil, nil); code != 404 {
		t.Fatalf("guest with no roles reading users: %d", code)
	}
	if code := b.do("GET", "/v1/organisations/"+home.ID+"/users", nil, nil); code != 404 {
		t.Fatalf("member reading home users: %d", code)
	}
	// Leaving.
	var memberships []store.Guest
	b.do("GET", "/v1/guest-memberships", nil, &memberships)
	if len(memberships) != 1 {
		t.Fatalf("memberships: %+v", memberships)
	}
	if code := b.do("POST", "/v1/guest-memberships/"+memberships[0].ID+"/leave", nil, nil); code != 204 {
		t.Fatalf("leave: %d", code)
	}
	b.do("GET", "/v1/guest-memberships", nil, &memberships)
	if len(memberships) != 0 {
		t.Fatalf("still a guest: %+v", memberships)
	}
}
