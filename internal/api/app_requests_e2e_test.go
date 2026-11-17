//go:build e2e

package api

import (
	"context"
	"testing"

	"github.com/thekestongroup/id/internal/secret"
	"github.com/thekestongroup/id/internal/store"
)

// App requests on Keston ID's account pages: what you can ask for, asking,
// the duplicate and daily limits, withdrawing and the outcome.
func TestAppRequestsOnAccountPages(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	app := "app" + secret.Hash(secret.Token())[:8]
	if _, err := e.st.DB.Exec(ctx, `INSERT INTO clients (id, name, publisher, redirect_uris) VALUES ($1, 'Plans', 'Someone', '{}')`, app); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetAppPolicy(ctx, e.orgID, app, store.AppDisabled); err != nil {
		t.Fatal(err)
	}
	bob := e.user("bob")
	b := e.browser()
	if f := b.signIn(bob.Email, goodPassword, ""); f.Step == "" {
		t.Fatalf("sign in: %+v", f)
	}
	var apps []struct{ ID string }
	if code := b.do("GET", "/v1/me/requestable-apps", nil, &apps); code != 200 || len(apps) == 0 {
		t.Fatalf("requestable: %d %+v", code, apps)
	}
	if code := b.do("POST", "/v1/me/app-requests", map[string]string{"clientId": app, "reason": ""}, nil); code != 422 {
		t.Errorf("no reason: %d", code)
	}
	var req store.AppRequest
	if code := b.do("POST", "/v1/me/app-requests", map[string]string{"clientId": app, "reason": "Planning"}, &req); code != 201 || req.Status != "pending" {
		t.Fatalf("request: %d %+v", code, req)
	}
	if code := b.do("POST", "/v1/me/app-requests", map[string]string{"clientId": app, "reason": "Again"}, nil); code != 409 {
		t.Errorf("duplicate: %d", code)
	}
	var mine []store.AppRequest
	if code := b.do("GET", "/v1/me/app-requests", nil, &mine); code != 200 || len(mine) != 1 {
		t.Fatalf("mine: %d %+v", code, mine)
	}
	if code := b.do("DELETE", "/v1/me/app-requests/"+req.ID, nil, nil); code != 204 {
		t.Errorf("withdraw: %d", code)
	}
	if code := b.do("DELETE", "/v1/me/app-requests/"+req.ID, nil, nil); code != 404 {
		t.Errorf("withdraw twice: %d", code)
	}
	// Decided by an admin: they see the outcome, then mark it seen.
	req2, err := e.st.CreateAppRequest(ctx, bob, app, "Planning again", "")
	if err != nil {
		t.Fatal(err)
	}
	org, _ := e.st.OrganisationByID(ctx, e.orgID)
	admin, _ := e.st.UserByEmail(ctx, "admin@"+org.Domain)
	if _, err := e.st.DeclineAppRequest(ctx, e.orgID, req2.ID, admin, "Not yet", ""); err != nil {
		t.Fatal(err)
	}
	b.do("GET", "/v1/me/app-requests", nil, &mine)
	if mine[0].Status != "declined" || mine[0].DecisionMessage != "Not yet" || mine[0].Seen {
		t.Errorf("outcome: %+v", mine[0])
	}
	if code := b.do("POST", "/v1/me/app-requests/seen", nil, nil); code != 204 {
		t.Errorf("seen: %d", code)
	}
	b.do("GET", "/v1/me/app-requests", nil, &mine)
	if !mine[0].Seen {
		t.Errorf("not marked seen: %+v", mine[0])
	}
}
