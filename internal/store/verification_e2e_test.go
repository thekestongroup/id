//go:build e2e

package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/thekestongroup/id/internal/db"
	"github.com/thekestongroup/id/internal/secret"
)

// Verification state in the store: new organisations can start unverified
// (and so can't sign in), verifying works once, and the platform
// organisation can never be unverified.
func TestOrganisationVerification(t *testing.T) {
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

	d := domain()
	org, admin, err := st.CreateOrganisation(ctx, "Plain", d, NewUser{Email: "a@" + d, Name: "A", PasswordHash: "x"})
	if err != nil || !org.Verified || org.VerifiedAt == nil || !admin.Usable() {
		t.Fatalf("CreateOrganisation is verified: %+v %v", org, err)
	}

	d = domain()
	org, admin, err = st.CreateOrganisationWith(ctx, "Waiting", d, NewUser{Email: "a@" + d, Name: "A", PasswordHash: "x"}, false)
	if err != nil || org.Verified || org.VerifiedAt != nil {
		t.Fatalf("unverified: %+v %v", org, err)
	}
	if admin.OrganisationVerified || admin.Usable() {
		t.Error("people in an unverified organisation are not usable accounts")
	}
	if ok, err := st.VerifyOrganisation(ctx, org.ID, admin.ID); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if ok, _ := st.VerifyOrganisation(ctx, org.ID, admin.ID); ok {
		t.Error("verifying twice reports a change")
	}
	got, _ := st.OrganisationByID(ctx, org.ID)
	u, _ := st.UserByID(ctx, admin.ID)
	if !got.Verified || !u.Usable() {
		t.Errorf("after verifying: %+v usable=%v", got, u.Usable())
	}

	// The platform organisation can't be unverified, even directly.
	var platformID string
	if err := pool.QueryRow(ctx, `SELECT id FROM organisations WHERE is_platform`).Scan(&platformID); err == nil {
		if _, err := pool.Exec(ctx, `UPDATE organisations SET verified_at = NULL WHERE id = $1`, platformID); err == nil {
			t.Error("platform organisation was unverified")
		}
		if p, _ := st.OrganisationByID(ctx, platformID); !p.Verified {
			t.Error("platform organisation not verified")
		}
	}

	// The setting defaults to off.
	if on, err := st.RequireOrganisationVerification(ctx); err != nil {
		t.Fatal(err)
	} else if on {
		t.Log("setting already on in this database")
	}
}
