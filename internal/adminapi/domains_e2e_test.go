//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// fakeDNS answers TXT lookups from a map; names it doesn't know are NXDOMAIN.
type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type brokenDNS struct{}

func (brokenDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", IsTemporary: true}
}

func uniqueDomain() string { return "d" + strings.ToLower(secret.Token()[:10]) + ".test" }

func (e *env) addDomain(as *store.User, org *store.Organisation, domain string, override bool) (int, store.OrgDomain, txtRecord) {
	e.t.Helper()
	code, raw := e.doIn(org, as, http.MethodPost, "/domains", map[string]any{"domain": domain, "override": override})
	var d struct {
		store.OrgDomain
		ID     string     `json:"id"`
		Record *txtRecord `json:"record"`
	}
	_ = json.Unmarshal(raw, &d)
	rec := txtRecord{}
	if d.Record != nil {
		rec = *d.Record
	}
	d.OrgDomain.ID = d.ID
	return code, d.OrgDomain, rec
}

func TestDomainVerification(t *testing.T) {
	e := setup(t)
	admin := e.admin()
	dom := uniqueDomain()

	code, d, rec := e.addDomain(admin, e.org, dom, false)
	if code != http.StatusCreated || d.Verified || d.Primary {
		t.Fatalf("add: %d %+v", code, d)
	}
	if rec.Name != "_keston-verification."+dom || !strings.HasPrefix(rec.Value, "keston-verify=") {
		t.Fatalf("record: %+v", rec)
	}

	// No record yet: refused, and still unverified.
	e.api.resolver = fakeDNS{}
	c, raw := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/verify", nil)
	if c != http.StatusUnprocessableEntity {
		t.Fatalf("verify without record: %d %s", c, raw)
	}
	// A wrong value doesn't count.
	e.api.resolver = fakeDNS{rec.Name: {"keston-verify=nope", "v=spf1 -all"}}
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/verify", nil); c != http.StatusUnprocessableEntity {
		t.Fatalf("verify with wrong record: %d", c)
	}
	// DNS trouble is a different error, not "the record is missing".
	e.api.resolver = brokenDNS{}
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/verify", nil); c != http.StatusBadGateway {
		t.Fatalf("verify with DNS down: %d", c)
	}
	// Unverified domains can't be used for emails or made primary.
	if c, raw := e.doIn(e.org, admin, http.MethodPost, "/users", map[string]any{"name": "Zed", "username": "zed",
		"password": "Correct-Horse-9-battery", "domain": dom}); c != http.StatusUnprocessableEntity {
		t.Fatalf("user on unverified domain: %d %s", c, raw)
	}
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/primary", nil); c != http.StatusConflict {
		t.Fatalf("primary while unverified: %d", c)
	}

	// The record is there: verified, audited once, and verifying again is harmless.
	e.api.resolver = fakeDNS{rec.Name: {rec.Value}}
	for i := 0; i < 2; i++ {
		if c, raw := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/verify", nil); c != http.StatusOK {
			t.Fatalf("verify %d: %d %s", i, c, raw)
		}
	}
	list, _ := e.st.OrganisationDomains(context.Background(), e.org.ID)
	if len(list) != 2 || !list[1].Verified || list[1].Override {
		t.Fatalf("domains: %+v", list)
	}
	var n int
	_ = e.st.DB.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1 AND organisation_id = $2`,
		store.ActionDomainVerified, e.org.ID).Scan(&n)
	if n != 1 {
		t.Errorf("verified audit entries: %d", n)
	}

	// The apex works for hosts that can't do subdomains.
	d2 := uniqueDomain()
	_, x, rec2 := e.addDomain(admin, e.org, d2, false)
	e.api.resolver = fakeDNS{d2: {rec2.Value}}
	if c, raw := e.doIn(e.org, admin, http.MethodPost, "/domains/"+x.ID+"/verify", nil); c != http.StatusOK {
		t.Fatalf("apex verify: %d %s", c, raw)
	}
}

func TestDomainsAreUniqueAcrossOrganisations(t *testing.T) {
	e := setup(t)
	other, otherAdmin := e.otherOrg("Other")
	dom := uniqueDomain()
	if c, _, _ := e.addDomain(e.admin(), e.org, dom, false); c != http.StatusCreated {
		t.Fatal(c)
	}
	// Case-insensitively, even while unverified, and another organisation's primary.
	if c, _, _ := e.addDomain(otherAdmin, other, strings.ToUpper(dom), false); c != http.StatusUnprocessableEntity {
		t.Errorf("same domain in another organisation: %d", c)
	}
	if c, _, _ := e.addDomain(e.admin(), e.org, other.Domain, false); c != http.StatusUnprocessableEntity {
		t.Errorf("another organisation's primary: %d", c)
	}
	if c, _, _ := e.addDomain(e.admin(), e.org, e.org.Domain, false); c != http.StatusUnprocessableEntity {
		t.Errorf("its own domain twice: %d", c)
	}
	if taken, _ := e.st.DomainTaken(context.Background(), strings.ToUpper(dom)); !taken {
		t.Error("an unverified domain should still count as taken")
	}
	// Not verified, so nobody can be moved to it by domain.
	if o, err := e.st.OrganisationByDomain(context.Background(), dom); err == nil {
		t.Errorf("unverified domain resolved to %s", o.Name)
	}
}

func TestDomainOverrideNeedsTKGAdmin(t *testing.T) {
	e := setup(t)
	dom := uniqueDomain()
	// Its own global admin can't skip DNS.
	if c, _, _ := e.addDomain(e.admin(), e.org, dom, true); c != http.StatusForbidden {
		t.Fatalf("override by a global admin: %d", c)
	}
	// A TKG Admin can, for an organisation they aren't in, without support access.
	_, staff := e.platformAdmin()
	c, d, _ := e.addDomain(staff, e.org, dom, true)
	if c != http.StatusCreated || !d.Verified || !d.Override || d.VerifiedByName != staff.Name {
		t.Fatalf("override: %d %+v", c, d)
	}
	if !e.auditHas(e.org.ID, store.ActionDomainAdded, "override") {
		t.Error("override not audited")
	}
	// It's usable straight away, and flagged in the list.
	code, raw := e.doIn(e.org, staff, http.MethodGet, "/domains", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), `"override":true`) || !strings.Contains(string(raw), `"canOverride":true`) {
		t.Fatalf("list: %d %s", code, raw)
	}
	// A member without Settings can't see or change domains.
	member := e.user("plain", "member")
	if c, _ := e.doIn(e.org, member, http.MethodGet, "/domains", nil); c != http.StatusForbidden && c != http.StatusNotFound {
		t.Errorf("member lists domains: %d", c)
	}
	// Another organisation's global admin can't touch them either.
	other, otherAdmin := e.otherOrg("Other")
	_ = other
	if c, _ := e.doIn(e.org, otherAdmin, http.MethodGet, "/domains", nil); c == http.StatusOK {
		t.Errorf("another organisation's admin lists domains")
	}
}

func TestUsersOnSecondaryDomain(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()
	_, staff := e.platformAdmin()
	second := uniqueDomain()
	_, d, _ := e.addDomain(staff, e.org, second, true)

	// Choosing the domain when creating; the default is the primary.
	c, raw := e.doIn(e.org, admin, http.MethodPost, "/users", map[string]any{"name": "Sam", "username": "sam",
		"password": "Correct-Horse-9-battery", "domain": second})
	if c != http.StatusCreated {
		t.Fatalf("create on secondary: %d %s", c, raw)
	}
	c, raw = e.doIn(e.org, admin, http.MethodPost, "/users", map[string]any{"name": "Sam", "username": "sam",
		"password": "Correct-Horse-9-battery"})
	if c != http.StatusCreated {
		t.Fatalf("same username on the primary is a different email: %d %s", c, raw)
	}
	// …but the same full email twice isn't.
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/users", map[string]any{"name": "Sam 2", "username": "sam",
		"password": "Correct-Horse-9-battery", "domain": second}); c != http.StatusUnprocessableEntity {
		t.Errorf("duplicate email: %d", c)
	}
	// Sign-in looks accounts up by full email, so the secondary works.
	u, err := e.st.UserByEmail(ctx, "SAM@"+second)
	if err != nil || u.OrganisationID != e.org.ID {
		t.Fatalf("lookup: %v %+v", err, u)
	}
	// Someone else's domain isn't one of ours.
	other, _ := e.otherOrg("Other")
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/users", map[string]any{"name": "Max", "username": "max",
		"password": "Correct-Horse-9-battery", "domain": other.Domain}); c != http.StatusUnprocessableEntity {
		t.Errorf("another organisation's domain: %d", c)
	}

	// It's in use, so it can't be removed; the primary can't either.
	if c, _ := e.doIn(e.org, admin, http.MethodDelete, "/domains/"+d.ID, nil); c != http.StatusConflict {
		t.Errorf("remove a domain in use: %d", c)
	}
	list, _ := e.st.OrganisationDomains(ctx, e.org.ID)
	if c, _ := e.doIn(e.org, admin, http.MethodDelete, "/domains/"+list[0].ID, nil); c != http.StatusConflict {
		t.Errorf("remove the primary: %d", c)
	}

	// Making it primary keeps existing emails…
	if c, raw := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/primary", nil); c != http.StatusOK {
		t.Fatalf("make primary: %d %s", c, raw)
	}
	if o, _ := e.st.OrganisationByID(ctx, e.org.ID); o.Domain != second {
		t.Errorf("organisations.domain = %s", o.Domain)
	}
	if _, err := e.st.UserByEmail(ctx, "admin@"+e.org.Domain); err != nil {
		t.Errorf("admin was renamed: %v", err)
	}
	// …a rename that would clash changes nothing…
	old := list[0].ID
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/domains/"+old+"/primary", nil); c != http.StatusOK {
		t.Fatalf("back to the first: %d", c)
	}
	if c, _ := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/primary", map[string]any{"renameUsers": true}); c != http.StatusConflict {
		t.Fatalf("clashing rename: %d", c)
	}
	// …and without the clash everyone moves.
	if _, err := e.st.DB.Exec(ctx, `UPDATE users SET email = 'sam2@' || $2 WHERE lower(email) = 'sam@' || $1`, e.org.Domain, e.org.Domain); err != nil {
		t.Fatal(err)
	}
	if c, raw := e.doIn(e.org, admin, http.MethodPost, "/domains/"+d.ID+"/primary", map[string]any{"renameUsers": true}); c != http.StatusOK {
		t.Fatalf("rename users: %d %s", c, raw)
	}
	if _, err := e.st.UserByEmail(ctx, "admin@"+second); err != nil {
		t.Errorf("admin not renamed: %v", err)
	}
	if !e.auditHas(e.org.ID, store.ActionDomainPrimary, "renamed") {
		t.Error("rename not audited")
	}
	// The old domain is now unused and can go.
	if c, raw := e.doIn(e.org, admin, http.MethodDelete, "/domains/"+old, nil); c != http.StatusNoContent {
		t.Errorf("remove the unused old domain: %d %s", c, raw)
	}
}

func TestOrganisationsStartWithTheirDomain(t *testing.T) {
	e := setup(t)
	list, err := e.st.OrganisationDomains(context.Background(), e.org.ID)
	if err != nil || len(list) != 1 || !list[0].Primary || !list[0].Verified || list[0].Domain != e.org.Domain {
		t.Fatalf("%v %+v", err, list)
	}
}
