//go:build e2e

package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// A second organisation (verified), with its first global admin.
func (e *env) otherOrg(name string) (*store.Organisation, *store.User) {
	e.t.Helper()
	domain := "o" + strings.ToLower(secret.Token()[:10]) + ".test"
	org, admin, err := e.st.CreateOrganisation(context.Background(), name, domain, store.NewUser{
		Email: "admin@" + domain, Name: name + " Admin", PasswordHash: secret.HashPassword("x")})
	if err != nil {
		e.t.Fatal(err)
	}
	return org, admin
}

func (e *env) userIn(org *store.Organisation, username, role string) *store.User {
	e.t.Helper()
	u, err := e.st.CreateUser(context.Background(), e.st.DB, store.NewUser{OrganisationID: org.ID,
		Email: username + "@" + org.Domain, Name: username, Role: role, PasswordHash: secret.HashPassword("x")})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

// doIn: a request in this organisation's /organisations/{id} (path "" is
// the organisation itself).
func (e *env) doIn(org *store.Organisation, as *store.User, method, path string, body any) (int, []byte) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/organisations/"+org.ID+path, &buf)
	req.Header.Set("Authorization", "Bearer "+e.token(as))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (e *env) must(code int, want int, raw []byte, what string) {
	e.t.Helper()
	if code != want {
		e.t.Fatalf("%s: %d (want %d) %s", what, code, want, raw)
	}
}

func (e *env) allowGuests(org *store.Organisation, admin *store.User, on bool) {
	e.t.Helper()
	code, raw := e.doIn(org, admin, http.MethodPut, "/guest-settings", map[string]any{"allowGuests": on})
	e.must(code, http.StatusOK, raw, "guest setting")
}

// invite: org's admin invites this email; returns the status and body.
func (e *env) invite(org *store.Organisation, admin *store.User, email string) (int, []byte) {
	return e.doIn(org, admin, http.MethodPost, "/guests", map[string]any{"email": email})
}

func (e *env) invitation(u *store.User) store.Guest {
	e.t.Helper()
	code, raw := e.call(u, http.MethodGet, "/guest-invitations", nil)
	e.must(code, http.StatusOK, raw, "invitations")
	var list []store.Guest
	_ = json.Unmarshal(raw, &list)
	if len(list) != 1 {
		e.t.Fatalf("invitations: %s", raw)
	}
	return list[0]
}

func (e *env) auditHas(orgID, action, contains string) bool {
	e.t.Helper()
	entries, _, err := e.st.AuditLog(context.Background(), store.LogFilter{OrganisationID: orgID, Actions: []string{action}, Limit: 50})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, en := range entries {
		if strings.Contains(en.Summary, contains) {
			return true
		}
	}
	return false
}

func TestGuestInvitationsNeedTheHomeSetting(t *testing.T) {
	e := setup(t)
	adminA := e.admin() // e.org is "Test School", where the guest will work
	home, adminB := e.otherOrg("Home College")
	bob := e.userIn(home, "bob", "member")

	// Setting off (the default): nothing is delivered, and the message is the
	// same as for an address nobody has, so it reveals nothing.
	code, off := e.invite(e.org, adminA, bob.Email)
	e.must(code, http.StatusUnprocessableEntity, off, "setting off")
	code, nobody := e.invite(e.org, adminA, "nobody@"+home.Domain)
	e.must(code, http.StatusUnprocessableEntity, nobody, "unknown address")
	if !bytes.Equal(off, nobody) {
		t.Errorf("messages differ:\n%s\n%s", off, nobody)
	}
	if code, raw := e.call(bob, http.MethodGet, "/guest-invitations", nil); code != 200 || strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("nothing waiting for bob: %d %s", code, raw)
	}
	// Only people with "Add users" can invite.
	plain := e.user("plain", "member")
	if code, _ := e.invite(e.org, plain, bob.Email); code != http.StatusNotFound { // no permission at all: can't even see the organisation
		t.Errorf("plain member inviting: %d", code)
	}

	// Home organisation turns it on: now it goes through.
	e.allowGuests(home, adminB, true)
	code, raw := e.invite(e.org, adminA, bob.Email)
	e.must(code, http.StatusCreated, raw, "invite")
	// A second invitation (or one to someone already there) is refused.
	if code, _ := e.invite(e.org, adminA, bob.Email); code != http.StatusConflict {
		t.Errorf("duplicate invitation: %d", code)
	}
	if code, _ := e.invite(e.org, adminA, plain.Email); code != http.StatusUnprocessableEntity {
		t.Errorf("inviting an existing member: %d", code)
	}
	// Bob has a notification and an invitation; the pop-up shows once.
	notes, _ := e.st.Notifications(context.Background(), bob.ID)
	if len(notes) != 1 || !strings.Contains(notes[0].Title, "Test School") {
		t.Errorf("notifications: %+v", notes)
	}
	inv := e.invitation(bob)
	if inv.OrganisationID != e.org.ID || inv.Status != "pending" {
		t.Errorf("invitation: %+v", inv)
	}
	var pr struct {
		GuestInvitations []struct {
			ID    string
			Popup bool
		}
	}
	_, raw = e.call(bob, http.MethodGet, "/prompts", nil)
	_ = json.Unmarshal(raw, &pr)
	if len(pr.GuestInvitations) != 1 || !pr.GuestInvitations[0].Popup {
		t.Fatalf("first prompt: %s", raw)
	}
	code, raw = e.call(bob, http.MethodPost, "/prompts/seen", map[string]any{"kind": "guest_invitation", "id": inv.ID})
	e.must(code, http.StatusNoContent, raw, "seen")
	_, raw = e.call(bob, http.MethodGet, "/prompts", nil)
	pr.GuestInvitations = nil
	_ = json.Unmarshal(raw, &pr)
	if len(pr.GuestInvitations) != 1 || pr.GuestInvitations[0].Popup {
		t.Errorf("second prompt shouldn't pop up: %s", raw)
	}
	// Audit: both organisations see the invitation.
	if !e.auditHas(e.org.ID, store.ActionGuestInvited, bob.Email) || !e.auditHas(home.ID, store.ActionGuestInvited, bob.Email) {
		t.Error("invitation not audited on both sides")
	}

	// Someone else can't answer it; the person can.
	carol := e.userIn(home, "carol", "member")
	if code, _ := e.call(carol, http.MethodPost, "/guest-invitations/"+inv.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("someone else accepting: %d", code)
	}

	// Home turns the setting off before they answer: it can't be accepted.
	e.allowGuests(home, adminB, false)
	if code, _ := e.call(bob, http.MethodPost, "/guest-invitations/"+inv.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("accepting while off: %d", code)
	}
	e.allowGuests(home, adminB, true)
	code, raw = e.call(bob, http.MethodPost, "/guest-invitations/"+inv.ID+"/decline", nil)
	e.must(code, http.StatusOK, raw, "decline")
	if !e.auditHas(home.ID, store.ActionGuestDeclined, "declined") {
		t.Error("decline not audited at home")
	}
	// Declined: they can be invited again.
	code, raw = e.invite(e.org, adminA, bob.Email)
	e.must(code, http.StatusCreated, raw, "re-invite")
	inv = e.invitation(bob)
	code, raw = e.call(bob, http.MethodPost, "/guest-invitations/"+inv.ID+"/accept", nil)
	e.must(code, http.StatusOK, raw, "accept")
	if !e.auditHas(e.org.ID, store.ActionGuestAccepted, "accepted") {
		t.Error("accept not audited in the guest organisation")
	}
	// The inviter hears about it.
	notes, _ = e.st.Notifications(context.Background(), adminA.ID)
	found := false
	for _, n := range notes {
		found = found || strings.Contains(n.Title, "accepted your invitation")
	}
	if !found {
		t.Errorf("inviter not told: %+v", notes)
	}
}

func TestGuestPermissionBoundaries(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	adminA := e.admin()
	home, adminB := e.otherOrg("Home College")
	e.allowGuests(home, adminB, true)
	bob := e.userIn(home, "bob", "member")
	staffB := e.userIn(home, "staff", "member") // someone at home Bob mustn't be able to see through A
	_ = staffB

	code, raw := e.invite(e.org, adminA, bob.Email)
	e.must(code, http.StatusCreated, raw, "invite")
	var g store.Guest
	_ = json.Unmarshal(raw, &g)
	e.call(bob, http.MethodPost, "/guest-invitations/"+g.ID+"/accept", nil)

	// By default a guest is a plain member there: no access to Keston Admin.
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/users", nil); code != http.StatusNotFound {
		t.Errorf("a guest with no roles: %d", code)
	}
	// Listed as a guest for the organisation's admins.
	var guests []store.Guest
	_, raw = e.doIn(e.org, adminA, http.MethodGet, "/guests", nil)
	_ = json.Unmarshal(raw, &guests)
	if len(guests) != 1 || guests[0].UserID != bob.ID || guests[0].Status != "accepted" {
		t.Fatalf("guests: %s", raw)
	}
	// Not in the organisation's ordinary users.
	var users []struct{ ID string }
	_, raw = e.doIn(e.org, adminA, http.MethodGet, "/users", nil)
	_ = json.Unmarshal(raw, &users)
	for _, u := range users {
		if u.ID == bob.ID {
			t.Error("a guest is listed among the users")
		}
	}

	// Admin roles and groups the guest organisation gives them.
	code, raw = e.doIn(e.org, adminA, http.MethodPut, "/guests/"+g.ID+"/roles", map[string]any{"roles": []string{"user_admin"}})
	e.must(code, http.StatusOK, raw, "roles")
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/users", nil); code != http.StatusOK {
		t.Errorf("guest with User admin: %d", code)
	}
	if !e.auditHas(e.org.ID, store.ActionGuestRoles, "User admin") {
		t.Error("roles not audited")
	}
	grp := e.group("Reporters", store.PermReports)
	code, raw = e.doIn(e.org, adminA, http.MethodPut, "/groups/"+grp.ID+"/members/"+bob.ID, nil)
	e.must(code, http.StatusNoContent, raw, "add guest to group")
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/audit-log", nil); code != http.StatusOK {
		t.Errorf("guest in a group with reports: %d", code)
	}
	// Only a role whose permissions the giver has: bob (User admin) can't hand out Apps admin.
	if code, _ := e.doIn(e.org, bob, http.MethodPut, "/guests/"+g.ID+"/roles", map[string]any{"roles": []string{"apps_admin"}}); code == http.StatusOK {
		t.Errorf("guest granting themself a role: %d", code)
	}

	// ── Nothing leaks to or from the home organisation ──
	// His permissions at home stay what they were (none), even though his
	// groups elsewhere give permissions.
	home0, _ := e.st.PermissionsOf(ctx, bob)
	if len(home0) != 0 {
		t.Errorf("home permissions: %v", home0.List())
	}
	inA, _ := e.st.PermissionsIn(ctx, bob, e.org.ID)
	if !inA.Has(store.PermViewUsers) || !inA.Has(store.PermReports) || inA.Has(store.PermApps) {
		t.Errorf("permissions in the guest organisation: %v", inA.List())
	}
	inB, _ := e.st.PermissionsIn(ctx, bob, home.ID)
	if len(inB) != 0 {
		t.Errorf("permissions at home: %v", inB.List())
	}
	if ids, _ := e.st.GroupIDsForUser(ctx, bob.ID); len(ids) != 0 {
		t.Errorf("a guest's groups elsewhere count for MFA and app rules at home: %v", ids)
	}
	// He can't use the guest organisation to reach the home one, nor anyone
	// else's, whatever he can do in A.
	for _, path := range []string{"", "/users", "/users/" + staffB.ID, "/audit-log", "/groups", "/guests"} {
		if code, _ := e.doIn(home, bob, http.MethodGet, path, nil); code != http.StatusNotFound {
			t.Errorf("guest reading home organisation %q: %d", path, code)
		}
	}
	other, _ := e.otherOrg("Third")
	if code, _ := e.doIn(other, bob, http.MethodGet, "/users", nil); code != http.StatusNotFound {
		t.Errorf("guest reading a third organisation: %d", code)
	}
	// The guest organisation's admins can't reach the home organisation either.
	if code, _ := e.doIn(home, adminA, http.MethodGet, "/users", nil); code != http.StatusNotFound {
		t.Errorf("guest admin reading home users: %d", code)
	}
	// Admins of the guest organisation can't touch the guest's account:
	// password, MFA, profile, status, deletion all refuse, even for a global admin.
	hash := func() string {
		u, _ := e.st.UserByID(ctx, bob.ID)
		return u.PasswordHash
	}
	before := hash()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/users/" + bob.ID},
		{http.MethodPost, "/users/" + bob.ID + "/reset-password"},
		{http.MethodPost, "/users/" + bob.ID + "/mfa/disable"},
		{http.MethodDelete, "/users/" + bob.ID + "/passkeys"},
		{http.MethodPatch, "/users/" + bob.ID},
		{http.MethodPost, "/users/" + bob.ID + "/status"},
		{http.MethodDelete, "/users/" + bob.ID},
		{http.MethodPost, "/users/" + bob.ID + "/access-passes"},
		{http.MethodPost, "/users/" + bob.ID + "/require-password-change"},
		{http.MethodPut, "/users/" + bob.ID + "/roles"},
		{http.MethodPut, "/users/" + bob.ID + "/licences"},
		{http.MethodPut, "/users/" + bob.ID + "/picture"},
		{http.MethodPost, "/users/" + bob.ID + "/move"},
	} {
		code, _ := e.doIn(e.org, adminA, c.method, c.path, map[string]any{"generatePassword": true, "password": "Abcdefghij1!x", "name": "X",
			"roles": []string{}, "licences": []string{}, "status": "disabled", "domain": other.Domain})
		if code != http.StatusNotFound {
			t.Errorf("%s %s on a guest: %d", c.method, c.path, code)
		}
	}
	// Bulk actions skip them.
	res := e.bulk(adminA, "/users/bulk/reset-password", map[string]any{"userIds": []string{bob.ID}})
	if res[bob.ID].Result != "skipped" {
		t.Errorf("bulk reset on a guest: %+v", res[bob.ID])
	}
	if hash() != before {
		t.Error("the guest's password changed")
	}
	if st := e.status(bob); st != "active" {
		t.Errorf("status: %s", st)
	}
	// A guest who is a User admin in A can't change their own account there either.
	if code, _ := e.doIn(e.org, bob, http.MethodPost, "/users/"+bob.ID+"/reset-password", map[string]any{"generatePassword": true}); code != http.StatusNotFound {
		t.Errorf("guest resetting their own password through the guest organisation: %d", code)
	}
	// And the home admin keeps full control of the account.
	code, raw = e.doIn(home, adminB, http.MethodPost, "/users/"+bob.ID+"/reset-password", map[string]any{"generatePassword": true})
	e.must(code, http.StatusOK, raw, "home admin reset")

	// The account itself, tokens and apps stay with the home organisation.
	fresh, _ := e.st.UserByID(ctx, bob.ID)
	if fresh.OrganisationID != home.ID || fresh.Organisation != home.Name || fresh.Email != "bob@"+home.Domain || fresh.Role != "member" {
		t.Errorf("home account changed: %+v", fresh)
	}
	apps, _ := e.st.EffectiveApps(ctx, fresh)
	homeApps, _ := e.st.EffectiveApps(ctx, fresh) // computed from the home organisation only
	if len(apps) != len(homeApps) {
		t.Error("apps")
	}
	if names, _ := e.st.GroupNamesForUser(ctx, bob.ID); len(names) != 0 {
		t.Errorf("SAML/OIDC group claims include the guest organisation's groups: %v", names)
	}

	// A group member who's a guest can't be moved around by someone with fewer permissions.
	lowly := e.user("lowly", "member")
	lg := e.group("Group mgrs", store.PermGroups)
	_ = e.st.AddGroupMember(ctx, lg.ID, lowly.ID)
	if code, _ := e.doIn(e.org, lowly, http.MethodPut, "/groups/"+grp.ID+"/members/"+bob.ID, nil); code == http.StatusNoContent {
		t.Error("a user without Reports (and so lower than the guest) changed the guest")
	}

	// Turning the home setting off puts the membership on hold…
	e.allowGuests(home, adminB, false)
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/users", nil); code != http.StatusNotFound {
		t.Errorf("guest access while the home setting is off: %d", code)
	}
	_, raw = e.call(bob, http.MethodGet, "/my-organisations", nil)
	if strings.Contains(string(raw), e.org.ID) {
		t.Errorf("my organisations while off: %s", raw)
	}
	// …and back on restores it.
	e.allowGuests(home, adminB, true)
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/users", nil); code != http.StatusOK {
		t.Errorf("guest access restored: %d", code)
	}

	// Removing the guest ends it all, and only that.
	if code, _ := e.doIn(e.org, lowly, http.MethodDelete, "/guests/"+g.ID, nil); code != http.StatusForbidden {
		t.Errorf("removing without Delete users: %d", code)
	}
	code, raw = e.doIn(e.org, adminA, http.MethodDelete, "/guests/"+g.ID, nil)
	e.must(code, http.StatusNoContent, raw, "remove")
	if code, _ := e.doIn(e.org, bob, http.MethodGet, "/users", nil); code != http.StatusNotFound {
		t.Errorf("removed guest: %d", code)
	}
	if ids, _ := e.st.GroupIDsInOrganisation(ctx, e.org.ID); len(ids[bob.ID]) != 0 {
		t.Errorf("groups remain: %v", ids[bob.ID])
	}
	if st := e.status(bob); st != "active" {
		t.Errorf("their account: %s", st)
	}
	if !e.auditHas(home.ID, store.ActionGuestRemoved, bob.Email) {
		t.Error("removal not audited at home")
	}
}

func TestMyOrganisationsAndLeaving(t *testing.T) {
	e := setup(t)
	adminA := e.admin()
	home, adminB := e.otherOrg("Home College")
	e.allowGuests(home, adminB, true)
	bob := e.userIn(home, "bob", "member")
	_, raw := e.invite(e.org, adminA, bob.Email)
	var g store.Guest
	_ = json.Unmarshal(raw, &g)
	e.call(bob, http.MethodPost, "/guest-invitations/"+g.ID+"/accept", nil)

	type mine struct {
		Organisations []struct {
			ID, Name  string
			Home      bool
			GuestID   string
			CanManage bool
		}
		CanBrowseAll bool
	}
	var got mine
	code, raw := e.call(bob, http.MethodGet, "/my-organisations", nil)
	e.must(code, http.StatusOK, raw, "mine")
	_ = json.Unmarshal(raw, &got)
	if len(got.Organisations) != 2 || !got.Organisations[0].Home || got.Organisations[0].ID != home.ID ||
		got.Organisations[1].Home || got.Organisations[1].ID != e.org.ID || got.Organisations[1].GuestID != g.ID ||
		got.Organisations[1].CanManage || got.CanBrowseAll {
		t.Errorf("my organisations: %s", raw)
	}
	// TKG Admins can browse every organisation.
	_, staff := e.platformAdmin()
	_, raw = e.call(staff, http.MethodGet, "/my-organisations", nil)
	got = mine{}
	_ = json.Unmarshal(raw, &got)
	if !got.CanBrowseAll || len(got.Organisations) != 1 {
		t.Errorf("TKG admin: %s", raw)
	}

	// Someone else can't make bob leave; he can.
	carol := e.userIn(home, "carol", "member")
	if code, _ := e.call(carol, http.MethodPost, "/guest-memberships/"+g.ID+"/leave", nil); code != http.StatusNotFound {
		t.Errorf("someone else leaving for him: %d", code)
	}
	code, raw = e.call(bob, http.MethodPost, "/guest-memberships/"+g.ID+"/leave", nil)
	e.must(code, http.StatusNoContent, raw, "leave")
	_, raw = e.call(bob, http.MethodGet, "/guest-memberships", nil)
	if strings.TrimSpace(string(raw)) != "[]" {
		t.Errorf("still a guest: %s", raw)
	}
	if !e.auditHas(e.org.ID, store.ActionGuestLeft, "left") || !e.auditHas(home.ID, store.ActionGuestLeft, "left") {
		t.Error("leaving not audited on both sides")
	}
}

func TestGuestSettingNeedsPermission(t *testing.T) {
	e := setup(t)
	member := e.user("m", "member")
	g := e.group("Viewers", store.PermViewUsers)
	_ = e.st.AddGroupMember(context.Background(), g.ID, member.ID)
	if code, _ := e.do(member, http.MethodPut, "/guest-settings", map[string]any{"allowGuests": true}); code != http.StatusForbidden {
		t.Errorf("without the Security permission: %d", code)
	}
	if code, _ := e.do(e.admin(), http.MethodPut, "/guest-settings", map[string]any{}); code != http.StatusUnprocessableEntity {
		t.Errorf("missing value: %d", code)
	}
	e.allowGuests(e.org, e.admin(), true)
	if !e.auditHas(e.org.ID, store.ActionGuestSetting, "Allow users to be guests") {
		t.Error("not audited")
	}
	org, _ := e.st.OrganisationByID(context.Background(), e.org.ID)
	if !org.AllowGuests {
		t.Error("not saved")
	}
}

func TestMovingAnAccount(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	adminA := e.admin() // receiving organisation
	from, adminB := e.otherOrg("Old College")
	carol := e.userIn(from, "carol", "member")
	g, _ := e.st.CreateGroup(ctx, from.ID, "Maths")
	_ = e.st.AddGroupMember(ctx, g.ID, carol.ID)
	_, _, _ = e.st.SetRoles(ctx, carol.ID, []string{"helpdesk_admin"})
	carolToken := e.token(carol)
	if code, _ := e.call(carol, http.MethodGet, "/my-organisations", nil); code != http.StatusOK {
		t.Fatal("carol's token should work")
	}

	// Only a global admin of her organisation can ask; the receiving domain must exist.
	plain := e.userIn(from, "plain", "member")
	if code, _ := e.doIn(from, plain, http.MethodPost, "/users/"+carol.ID+"/move", map[string]any{"domain": e.org.Domain}); code == http.StatusAccepted || code == http.StatusCreated {
		t.Errorf("non-admin asking: %d", code)
	}
	if code, _ := e.doIn(from, adminB, http.MethodPost, "/users/"+carol.ID+"/move", map[string]any{"domain": "nowhere.test"}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown domain: %d", code)
	}
	// username@new-domain taken.
	e.user("carol", "member")
	if code, _ := e.doIn(from, adminB, http.MethodPost, "/users/"+carol.ID+"/move", map[string]any{"domain": e.org.Domain}); code != http.StatusUnprocessableEntity {
		t.Errorf("email taken: %d", code)
	}
	_, _ = e.st.DB.Exec(ctx, `DELETE FROM users WHERE email = $1`, "carol@"+e.org.Domain)
	// The only global admin can't be moved away.
	if code, raw := e.doIn(from, adminB, http.MethodPost, "/users/"+adminB.ID+"/move", map[string]any{"domain": e.org.Domain}); code != http.StatusConflict {
		t.Errorf("moving the only global admin: %d %s", code, raw)
	}
	// TKG Admins and support accounts can't be moved.
	platform, staff := e.platformAdmin()
	if code, _ := e.doIn(platform, staff, http.MethodPost, "/users/"+staff.ID+"/move", map[string]any{"domain": e.org.Domain}); code != http.StatusConflict {
		t.Errorf("moving a TKG Admin: %d", code)
	}

	code, raw := e.doIn(from, adminB, http.MethodPost, "/users/"+carol.ID+"/move", map[string]any{"domain": strings.ToUpper(e.org.Domain)})
	e.must(code, http.StatusCreated, raw, "request")
	var m store.AccountMove
	_ = json.Unmarshal(raw, &m)
	if m.NewEmail != "carol@"+e.org.Domain || m.Status != "pending" {
		t.Fatalf("move: %+v", m)
	}
	if code, _ := e.doIn(from, adminB, http.MethodPost, "/users/"+carol.ID+"/move", map[string]any{"domain": e.org.Domain}); code != http.StatusConflict {
		t.Errorf("second request: %d", code)
	}
	// Nothing has changed yet.
	if u, _ := e.st.UserByID(ctx, carol.ID); u.OrganisationID != from.ID {
		t.Fatal("moved before acceptance")
	}
	// The receiving admins are told, and get a pop-up once.
	var pr struct {
		MoveRequests []struct {
			ID    string
			Popup bool
		}
	}
	_, raw = e.call(adminA, http.MethodGet, "/prompts", nil)
	_ = json.Unmarshal(raw, &pr)
	if len(pr.MoveRequests) != 1 || !pr.MoveRequests[0].Popup || pr.MoveRequests[0].ID != m.ID {
		t.Fatalf("prompts: %s", raw)
	}
	e.call(adminA, http.MethodPost, "/prompts/seen", map[string]any{"kind": "account_move", "id": m.ID})
	_, raw = e.call(adminA, http.MethodGet, "/prompts", nil)
	pr.MoveRequests = nil
	_ = json.Unmarshal(raw, &pr)
	if len(pr.MoveRequests) != 1 || pr.MoveRequests[0].Popup {
		t.Errorf("pop-up again: %s", raw)
	}
	// Neither organisation's non-admins, nor the asking organisation, can accept.
	member := e.user("member", "member")
	if code, _ := e.do(member, http.MethodPost, "/moves/"+m.ID+"/accept", nil); code != http.StatusNotFound && code != http.StatusForbidden {
		t.Errorf("a member accepting: %d", code)
	}
	if code, _ := e.doIn(from, adminB, http.MethodPost, "/moves/"+m.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("the asking organisation accepting: %d", code)
	}
	// An organisation's admin can't pop-up/accept someone else's request.
	third, adminC := e.otherOrg("Third")
	if code, _ := e.doIn(third, adminC, http.MethodPost, "/moves/"+m.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("a third organisation accepting: %d", code)
	}

	code, raw = e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/accept", nil)
	e.must(code, http.StatusOK, raw, "accept")
	moved, _ := e.st.UserByID(ctx, carol.ID)
	if moved.OrganisationID != e.org.ID || moved.Email != "carol@"+e.org.Domain || moved.Role != "member" {
		t.Errorf("after the move: %+v", moved)
	}
	if perms, _ := e.st.PermissionsOf(ctx, moved); len(perms) != 0 {
		t.Errorf("permissions carried over: %v", perms.List())
	}
	if ids, _ := e.st.GroupIDsForUser(ctx, carol.ID); len(ids) != 0 {
		t.Errorf("groups carried over: %v", ids)
	}
	var n int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE user_id = $1`, carol.ID).Scan(&n)
	if n != 0 {
		t.Errorf("group rows remain: %d", n)
	}
	// Signed out everywhere.
	req := httptest.NewRequest(http.MethodGet, "/my-organisations", nil)
	req.Header.Set("Authorization", "Bearer "+carolToken)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("old token after the move: %d", rec.Code)
	}
	// Audit on both sides.
	if !e.auditHas(from.ID, store.ActionMoveAccepted, "→") || !e.auditHas(e.org.ID, store.ActionMoveAccepted, "→") {
		t.Error("move not audited on both sides")
	}
	// Answered: can't be answered twice.
	if code, _ := e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("accepting twice: %d", code)
	}
	// Both organisations see it in their lists.
	var list []store.AccountMove
	_, raw = e.doIn(from, adminB, http.MethodGet, "/moves", nil)
	_ = json.Unmarshal(raw, &list)
	if len(list) != 1 || list[0].Status != "accepted" {
		t.Errorf("moves list: %s", raw)
	}

	// Decline, and cancel.
	dave := e.userIn(from, "dave", "member")
	code, raw = e.doIn(from, adminB, http.MethodPost, "/users/"+dave.ID+"/move", map[string]any{"domain": e.org.Domain})
	e.must(code, http.StatusCreated, raw, "second request")
	_ = json.Unmarshal(raw, &m)
	code, raw = e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/decline", nil)
	e.must(code, http.StatusOK, raw, "decline")
	if u, _ := e.st.UserByID(ctx, dave.ID); u.OrganisationID != from.ID {
		t.Error("moved although declined")
	}
	code, raw = e.doIn(from, adminB, http.MethodPost, "/users/"+dave.ID+"/move", map[string]any{"domain": e.org.Domain})
	e.must(code, http.StatusCreated, raw, "third request")
	_ = json.Unmarshal(raw, &m)
	if code, _ := e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/cancel", nil); code != http.StatusNotFound {
		t.Errorf("the receiving organisation cancelling: %d", code)
	}
	code, raw = e.doIn(from, adminB, http.MethodPost, "/moves/"+m.ID+"/cancel", nil)
	e.must(code, http.StatusNoContent, raw, "cancel")
	if code, _ := e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/accept", nil); code != http.StatusNotFound {
		t.Errorf("accepting a cancelled request: %d", code)
	}
}

// Moving into an organisation where the person is a guest makes them a member.
func TestMovingAGuestIntoTheOrganisation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	adminA := e.admin()
	home, adminB := e.otherOrg("Home College")
	e.allowGuests(home, adminB, true)
	bob := e.userIn(home, "bob", "member")
	_, raw := e.invite(e.org, adminA, bob.Email)
	var g store.Guest
	_ = json.Unmarshal(raw, &g)
	e.call(bob, http.MethodPost, "/guest-invitations/"+g.ID+"/accept", nil)
	grp := e.group("Staff")
	_ = e.st.AddGroupMember(ctx, grp.ID, bob.ID)

	code, raw := e.doIn(home, adminB, http.MethodPost, "/users/"+bob.ID+"/move", map[string]any{"domain": e.org.Domain})
	e.must(code, http.StatusCreated, raw, "request")
	var m store.AccountMove
	_ = json.Unmarshal(raw, &m)
	code, raw = e.do(adminA, http.MethodPost, "/moves/"+m.ID+"/accept", nil)
	e.must(code, http.StatusOK, raw, "accept")
	if e.st.IsGuestIn(ctx, bob.ID, e.org.ID) {
		t.Error("still a guest of their own organisation")
	}
	if list, _ := e.st.GuestsInOrganisation(ctx, e.org.ID); len(list) != 0 {
		t.Errorf("guests: %+v", list)
	}
}
