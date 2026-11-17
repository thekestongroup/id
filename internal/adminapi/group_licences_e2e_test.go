//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/store"
)

// Group licences: a group gives its members licences; direct and group
// licences share one seat; seats run out in a fixed order without ever
// taking a licence away; removing from a group or the group's licence takes
// away only what came through it.
func TestGroupLicensing(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris, builtin)
		VALUES ('work', 'Keston Work', 'The Keston Group', '{}', true) ON CONFLICT (id) DO UPDATE SET builtin = true`); err != nil {
		t.Fatal(err)
	}
	admin := e.admin() // has a direct "work" licence: one seat
	a, b, c, d := e.user("a", "member"), e.user("b", "member"), e.user("c", "member"), e.user("d", "member")
	g := e.group("Teachers")

	setSeats := func(n *int) {
		t.Helper()
		if _, err := e.st.SetAllocations(ctx, e.org.ID, nil, map[string]*int{"work": n}); err != nil {
			t.Fatal(err)
		}
	}
	licensed := func(u *store.User) bool {
		t.Helper()
		ok, err := e.st.Licensed(ctx, u, "work") // what sign-in checks
		if err != nil {
			t.Fatal(err)
		}
		l, _ := e.st.Licences(ctx, u.ID)
		if ok != slices.Contains(l, "work") {
			t.Fatalf("%s: Licensed %v but Licences %v", u.Name, ok, l)
		}
		return ok
	}
	product := func() store.Product {
		t.Helper()
		code, raw := e.do(admin, http.MethodGet, "/products", nil)
		var list []store.Product
		if code != http.StatusOK || json.Unmarshal(raw, &list) != nil {
			t.Fatalf("products: %d %s", code, raw)
		}
		for _, p := range list {
			if p.ID == "work" {
				return p
			}
		}
		t.Fatal("no work")
		return store.Product{}
	}
	expectLicensed := func(want string) {
		t.Helper()
		var got []string
		for _, u := range []*store.User{a, b, c, d} {
			if licensed(u) {
				got = append(got, u.Name)
			}
		}
		if strings.Join(got, "") != want {
			t.Errorf("licensed: got %v, want %q", got, want)
		}
	}
	// Join times are set explicitly so the order is the test's, not the clock's.
	join := func(u *store.User, minutes int) {
		t.Helper()
		if err := e.st.AddGroupMember(ctx, g.ID, u.ID); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(time.Duration(minutes-100) * time.Minute)
		if _, err := e.st.DB.Exec(ctx, `UPDATE group_members SET added_at = $3 WHERE group_id = $1 AND user_id = $2`,
			g.ID, u.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	putGroup := func(products ...string) (int, []byte) {
		return e.do(admin, http.MethodPut, "/groups/"+g.ID+"/licences", map[string]any{"products": products})
	}

	// Unlimited: a group licence reaches every member, and nobody else.
	join(c, 1) // joined first, though added later below: order is by join time
	join(a, 2)
	join(b, 3)
	join(d, 4)
	expectLicensed("")
	if code, raw := putGroup("work"); code != http.StatusOK {
		t.Fatalf("put group licences: %d %s", code, raw)
	}
	if code, _ := putGroup("nope"); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown product: %d", code)
	}
	expectLicensed("abcd")
	if p := product(); p.Assigned != 5 || len(p.Groups) != 1 || p.Groups[0].Name != "Teachers" || p.Unlicensed != 0 {
		t.Errorf("product: %+v", p)
	}
	var logged int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND organisation_id = $2
		AND summary LIKE '%Keston Work%'`, store.ActionGroupLicences, e.org.ID).Scan(&logged)
	if logged != 1 {
		t.Errorf("audit entries for group licence: %d", logged)
	}

	// Seats: the admin's direct licence plus two. Members past them are not
	// licensed, in join order (c, a, b, d): c and a get the seats.
	setSeats(ptr(3))
	expectLicensed("ac")
	p := product()
	if p.Assigned != 3 || p.Unlicensed != 2 || *p.Available != 0 || p.OverAllocated {
		t.Errorf("full: %+v", p)
	}
	var issues struct {
		Products []string
		Issues   []store.LicenceIssue
	}
	code, raw := e.do(admin, http.MethodGet, "/groups/"+g.ID+"/licences", nil)
	if code != http.StatusOK || json.Unmarshal(raw, &issues) != nil || len(issues.Issues) != 2 ||
		issues.Issues[0].UserID != b.ID || issues.Issues[1].UserID != d.ID {
		t.Fatalf("issues: %d %s", code, raw)
	}
	sum, err := e.st.OrganisationSummary(ctx, e.org.ID)
	if err != nil || sum.Licences.Unlicensed != 2 || sum.Licences.UnlicensedByProduct["work"] != 2 {
		t.Errorf("summary: %+v %v", sum.Licences, err)
	}

	// The user page says where each licence comes from and who has no seat.
	userPage := func(u *store.User) []store.LicenceSource {
		code, raw := e.do(admin, http.MethodGet, "/users/"+u.ID, nil)
		var out struct{ LicenceSources []store.LicenceSource }
		if code != http.StatusOK || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("user: %d %s", code, raw)
		}
		return out.LicenceSources
	}
	if s := userPage(c); len(s) != 1 || s[0].Direct || !s[0].Licensed || len(s[0].Groups) != 1 || s[0].Groups[0].Name != "Teachers" {
		t.Errorf("c sources: %+v", s)
	}
	if s := userPage(b); len(s) != 1 || s[0].Licensed {
		t.Errorf("b sources: %+v", s)
	}

	// Direct + group: one seat. a is licensed through the group; assigning it
	// directly too needs no seat, even though everything is full.
	code, raw = e.do(admin, http.MethodPut, "/users/"+a.ID+"/licences", map[string]any{"products": []string{"work"}})
	if code != http.StatusOK {
		t.Fatalf("direct for a: %d %s", code, raw)
	}
	if p = product(); p.Assigned != 3 {
		t.Errorf("a counted twice: %+v", p)
	}
	if s := userPage(a); len(s) != 1 || !s[0].Direct || len(s[0].Groups) != 1 {
		t.Errorf("a sources: %+v", s)
	}
	// Someone with no seat can't be assigned one directly: full.
	if code, _ = e.do(admin, http.MethodPut, "/users/"+b.ID+"/licences", map[string]any{"products": []string{"work"}}); code != http.StatusConflict {
		t.Errorf("direct for b when full: %d", code)
	}
	// Manage licences doesn't turn group licences into direct ones: c has
	// nothing direct to remove, and keeps the group's.
	code, _ = e.do(admin, http.MethodPost, "/users/bulk/licences", map[string]any{
		"userIds": []string{c.ID}, "remove": []string{"work"}})
	if code != http.StatusOK || !licensed(c) {
		t.Errorf("bulk remove touched a group licence: %d", code)
	}

	// Removal: a leaves the group and keeps its direct licence; c leaves and
	// loses its seat, which goes to b (next in order), not d.
	if code, _ = e.do(admin, http.MethodDelete, "/groups/"+g.ID+"/members/"+a.ID, nil); code != http.StatusNoContent {
		t.Fatalf("remove a: %d", code)
	}
	expectLicensed("ac")
	if code, _ = e.do(admin, http.MethodDelete, "/groups/"+g.ID+"/members/"+c.ID, nil); code != http.StatusNoContent {
		t.Fatalf("remove c: %d", code)
	}
	expectLicensed("ab")

	// Nothing is taken away when seats shrink below what direct licences use:
	// the admin and a keep theirs; group-only members have no seats left.
	setSeats(ptr(1))
	expectLicensed("a")
	if ok, _ := e.st.Licensed(ctx, admin, "work"); !ok {
		t.Error("admin lost a direct licence")
	}
	if p = product(); !p.OverAllocated || p.Assigned != 2 {
		t.Errorf("over allocation: %+v", p)
	}
	setSeats(nil)
	expectLicensed("abd")
	setSeats(ptr(3))
	expectLicensed("ab") // one seat for group-only members: b joined before d

	// Bulk Manage members: adding to a licensed group says who has no seat.
	res := e.bulk(admin, "/users/bulk/add-to-group", map[string]any{"groupId": g.ID, "userIds": ids(c, d)})
	if r := res[c.ID]; r.Result != "done" || !strings.Contains(r.Reason, "no Keston Work licences left") {
		t.Errorf("bulk add c: %+v", r)
	}
	// Removing the group's licence: members lose what came through it, the
	// direct licence (a) stays.
	if code, raw = putGroup(); code != http.StatusOK {
		t.Fatalf("clear group licences: %d %s", code, raw)
	}
	expectLicensed("a")
	if l, _ := e.st.Licences(ctx, admin.ID); !slices.Equal(l, []string{"work"}) {
		t.Errorf("admin: %v", l)
	}
}

func ptr(n int) *int { return &n }
