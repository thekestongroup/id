//go:build e2e

package adminapi

import (
	"context"
	"net/http"
	"testing"
)

func TestDeleteOrganisationNow(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	platform, staff := e.platformAdmin()
	orgAdmin := e.admin()
	path := func(id string) string { return "/organisations/" + id + "/delete-now" }

	// Not scheduled: 409, and nothing is deleted.
	if code, raw := e.call(staff, http.MethodPost, path(e.org.ID), nil); code != http.StatusConflict {
		t.Fatalf("not scheduled: %d %s", code, raw)
	}
	if _, err := e.st.OrganisationByID(ctx, e.org.ID); err != nil {
		t.Fatalf("organisation deleted though it wasn't scheduled: %v", err)
	}

	// The platform organisation can never be deleted, even if "scheduled".
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET delete_after = now() WHERE id = $1`, platform.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call(staff, http.MethodPost, path(platform.ID), nil); code != http.StatusConflict {
		t.Errorf("platform organisation: %d", code)
	}
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET delete_after = NULL WHERE id = $1`, platform.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.OrganisationByID(ctx, platform.ID); err != nil {
		t.Fatalf("platform organisation gone: %v", err)
	}

	// Scheduled (14 days to go): its own admin can't skip the wait.
	if _, err := e.st.ScheduleDeletion(ctx, e.org.ID, orgAdmin.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.call(orgAdmin, http.MethodPost, path(e.org.ID), nil); code != http.StatusForbidden {
		t.Errorf("organisation's own admin: %d", code)
	}
	if _, err := e.st.OrganisationByID(ctx, e.org.ID); err != nil {
		t.Fatalf("organisation deleted by its own admin: %v", err)
	}

	// A TKG Admin deletes it at once: organisation and users go, an audit
	// entry stays in the platform organisation's log.
	member := e.user("bo", "member")
	if code, raw := e.call(staff, http.MethodPost, path(e.org.ID), nil); code != http.StatusNoContent {
		t.Fatalf("delete now: %d %s", code, raw)
	}
	if _, err := e.st.OrganisationByID(ctx, e.org.ID); err == nil {
		t.Error("organisation still exists")
	}
	var users int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE id IN ($1, $2)`, orgAdmin.ID, member.ID).Scan(&users)
	if users != 0 {
		t.Errorf("%d of its users remain", users)
	}
	var n int
	_ = e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action = 'organisation.deleted_now'
		AND actor_id = $2 AND target_id = $3 AND target_name = $4 AND summary LIKE $5`,
		platform.ID, staff.ID, e.org.ID, e.org.Name, "%"+e.org.Domain+"%").Scan(&n)
	if n != 1 {
		t.Errorf("audit entries in the platform log: %d", n)
	}
	// Gone, so a second try is a 404 (not found), not a second deletion.
	if code, _ := e.call(staff, http.MethodPost, path(e.org.ID), nil); code != http.StatusNotFound {
		t.Errorf("deleting twice: %d", code)
	}
}
