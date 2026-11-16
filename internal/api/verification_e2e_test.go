//go:build e2e

package api

import (
	"context"
	"testing"
)

// People in an unverified organisation can't sign in, with a clear message
// (only once they've proved who they are), and a session they already had
// stops working.
func TestUnverifiedOrganisationCantSignIn(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	const email = "admin@"
	org, err := e.st.OrganisationByID(ctx, e.orgID)
	if err != nil {
		t.Fatal(err)
	}
	signInEmail := email + org.Domain

	// Signed in before the organisation became unverified.
	b := e.browser()
	if f := b.signIn(signInEmail, goodPassword, ""); f.Step != "account" {
		t.Fatalf("verified organisation: %+v", f)
	}
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET verified_at = NULL WHERE id = $1`, e.orgID); err != nil {
		t.Fatal(err)
	}
	var f flowOut
	if code := b.do("GET", "/flow", nil, &f); code != 200 || f.Step != "sign-in" {
		t.Errorf("existing session still works: %d %+v", code, f)
	}

	// Signing in: the right password gets the clear message…
	var res flowOut
	code := e.browser().do("POST", "/sign-in", map[string]string{"email": signInEmail, "password": goodPassword}, &res)
	want := "Your organisation is waiting to be verified. When it's verified, you'll be able to sign in."
	if code != 403 || res.Message != want {
		t.Errorf("right password: %d %+v", code, res)
	}
	// …a wrong one doesn't reveal anything.
	res = flowOut{}
	code = e.browser().do("POST", "/sign-in", map[string]string{"email": signInEmail, "password": "nope nope nope"}, &res)
	if code != 422 || res.Message != "Incorrect email or password" {
		t.Errorf("wrong password: %d %+v", code, res)
	}

	// Verified: signing in works again.
	if _, err := e.st.VerifyOrganisation(ctx, e.orgID, mustAdmin(t, e, signInEmail)); err != nil {
		t.Fatal(err)
	}
	if f := e.browser().signIn(signInEmail, goodPassword, ""); f.Step != "account" {
		t.Errorf("after verifying: %+v", f)
	}
}

func mustAdmin(t *testing.T, e *env, email string) string {
	t.Helper()
	u, err := e.st.UserByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}
