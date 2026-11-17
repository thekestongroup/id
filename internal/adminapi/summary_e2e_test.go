//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/store"
)

type summaryBody struct {
	store.OrgSummary
	RecentActivity *[]store.AuditRecord `json:"recentActivity"`
}

// GET …/summary: counts for the dashboard, in one request.
func TestOrganisationSummary(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()

	disabled := e.user("gone", "member")
	locked := e.user("locked", "member")
	mfa := e.user("mfa", "member")
	e.user("plain", "member")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := e.st.DB.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE users SET status = 'disabled' WHERE id = $1`, disabled.ID)
	exec(`UPDATE users SET locked_until = now() + interval '1 hour' WHERE id = $1`, locked.ID)
	exec(`UPDATE users SET totp_enabled = true WHERE id = $1`, mfa.ID)
	exec(`UPDATE users SET password_change_required = true WHERE id = $1`, mfa.ID)
	e.group("Teachers")
	e.group("Office")

	// Sign-ins: two today (one failed), one three days ago, one far outside the window,
	// and one in another organisation.
	log := func(ok bool, ago string, org string) {
		exec(`INSERT INTO sign_in_log (organisation_id, method, success, created_at)
			VALUES ($1, 'password', $2, now() - $3::interval)`, org, ok, ago)
	}
	log(true, "0 seconds", e.org.ID)
	log(false, "0 seconds", e.org.ID)
	log(true, "3 days", e.org.ID)
	log(true, "30 days", e.org.ID)
	_, staff := e.platformAdmin()
	other := staff.OrganisationID
	log(true, "0 seconds", other)

	get := func(as *store.User, org string) (int, summaryBody) {
		code, raw := e.call(as, http.MethodGet, "/organisations/"+org+"/summary", nil)
		var s summaryBody
		if code == http.StatusOK {
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("%v: %s", err, raw)
			}
			if strings.Contains(string(raw), "@") {
				t.Errorf("summary mentions an email address: %s", raw)
			}
		}
		return code, s
	}

	code, s := get(admin, e.org.ID)
	if code != http.StatusOK {
		t.Fatalf("summary: %d", code)
	}
	// admin, locked, mfa, plain are active or locked; gone is disabled.
	if u := s.Users; u.Total != 5 || u.Active != 3 || u.Disabled != 1 || u.Locked != 1 || u.PasswordChangeRequired != 1 {
		t.Errorf("users: %+v", u)
	}
	if s.MFA.Eligible != 4 || s.MFA.Enrolled != 1 || s.MFA.Mode != "required" {
		t.Errorf("mfa: %+v", s.MFA)
	}
	if s.Groups != 2 {
		t.Errorf("groups: %d", s.Groups)
	}
	if s.Apps.Enabled > s.Apps.Available {
		t.Errorf("apps: %+v", s.Apps)
	}
	if s.Licences.InUse < s.Licences.LicensedUsers {
		t.Errorf("licences: %+v", s.Licences)
	}
	if len(s.SignIns.Daily) != store.SummaryDays || s.SignIns.Total != 3 || s.SignIns.Failed != 1 {
		t.Fatalf("sign-ins: %+v", s.SignIns)
	}
	today := s.SignIns.Daily[len(s.SignIns.Daily)-1]
	if today.Date != time.Now().UTC().Format("2006-01-02") || today.Success != 1 || today.Failed != 1 {
		t.Errorf("today: %+v", today)
	}
	if s.SignIns.Daily[len(s.SignIns.Daily)-4].Success != 1 {
		t.Errorf("three days ago: %+v", s.SignIns.Daily)
	}
	if s.RecentActivity == nil {
		t.Error("a global admin should get recent activity")
	}

	// A member with no permissions can't see the organisation at all; one who
	// can manage users sees counts but not the audit log.
	plain := e.user("nobody", "member")
	if code, _ := get(plain, e.org.ID); code != http.StatusNotFound {
		t.Errorf("no permissions: %d", code)
	}
	helper := e.user("helper", "member")
	if err := e.st.AddGroupMember(ctx, e.group("Helpdesk", store.PermViewUsers).ID, helper.ID); err != nil {
		t.Fatal(err)
	}
	if code, hs := get(helper, e.org.ID); code != http.StatusOK || hs.RecentActivity != nil || hs.Users.Total < 5 {
		t.Errorf("helper: %d %+v", code, hs)
	}

	// Keston staff without support access get no counts (see
	// billing_access_e2e_test.go), and an organisation's admin can't see
	// another's.
	if code, _ := get(staff, e.org.ID); code != http.StatusForbidden {
		t.Errorf("platform admin: %d, want 403", code)
	}
	if code, _ := get(admin, other); code != http.StatusNotFound {
		t.Errorf("another organisation: %d", code)
	}
	if code, _ := get(admin, "00000000-0000-0000-0000-000000000000"); code != http.StatusNotFound {
		t.Errorf("unknown organisation: %d", code)
	}
}

// A new organisation has nothing to count yet.
func TestOrganisationSummaryEmpty(t *testing.T) {
	e := setup(t)
	code, raw := e.call(e.admin(), http.MethodGet, "/organisations/"+e.org.ID+"/summary", nil)
	var s summaryBody
	_ = json.Unmarshal(raw, &s)
	if code != http.StatusOK || s.Users.Total != 1 || s.Groups != 0 || s.SignIns.Total != 0 || len(s.SignIns.Daily) != store.SummaryDays {
		t.Fatalf("%d %s", code, raw)
	}
}
