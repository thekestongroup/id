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

func TestDeleteOrganisationNow(t *testing.T) {
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
	domain := func() string { return "t" + strings.ToLower(secret.Token()[:10]) + ".test" }
	platform, err := st.EnsurePlatformOrganisation(ctx, "The Keston Group", domain())
	if err != nil {
		t.Fatal(err)
	}
	d := domain()
	org, admin, err := st.CreateOrganisation(ctx, "Doomed", d, NewUser{Email: "a@" + d, Name: "A", PasswordHash: "x"})
	if err != nil {
		t.Fatal(err)
	}

	// Not scheduled, and the platform organisation: refused, nothing deleted.
	if _, err := st.DeleteOrganisationNow(ctx, org.ID, admin, ""); !errors.Is(err, ErrNotScheduled) {
		t.Errorf("not scheduled: %v", err)
	}
	if _, err := st.DeleteOrganisationNow(ctx, platform.ID, admin, ""); !errors.Is(err, ErrIsPlatform) {
		t.Errorf("platform: %v", err)
	}
	if _, err := st.OrganisationByID(ctx, org.ID); err != nil {
		t.Fatalf("deleted though refused: %v", err)
	}

	// Scheduled: deleted immediately, users included, audited in the platform log.
	if _, err := st.ScheduleDeletion(ctx, org.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
	got, err := st.DeleteOrganisationNow(ctx, org.ID, admin, "203.0.113.9")
	if err != nil || got.DeleteAfter == nil || got.Name != "Doomed" {
		t.Fatalf("delete now: %+v %v", got, err)
	}
	if _, err := st.OrganisationByID(ctx, org.ID); err == nil {
		t.Error("organisation remains")
	}
	if _, err := st.UserByID(ctx, admin.ID); err == nil {
		t.Error("user remains")
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE organisation_id = $1 AND action = $2 AND target_id = $3`,
		platform.ID, ActionOrganisationDeletedNow, org.ID).Scan(&n)
	if n != 1 {
		t.Errorf("platform audit entries: %d", n)
	}

	// Housekeeping shares the path: a due organisation still goes.
	d = domain()
	due, _, err := st.CreateOrganisation(ctx, "Due", d, NewUser{Email: "a@" + d, Name: "A", PasswordHash: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE organisations SET delete_after = now() - interval '1 minute' WHERE id = $1`, due.ID); err != nil {
		t.Fatal(err)
	}
	names, err := st.DeleteDueOrganisations(ctx)
	if err != nil || len(names) == 0 {
		t.Fatalf("housekeeping: %v %v", names, err)
	}
	if _, err := st.OrganisationByID(ctx, due.ID); err == nil {
		t.Error("due organisation remains")
	}
}
