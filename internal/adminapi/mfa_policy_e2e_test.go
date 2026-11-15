//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

// Settings → Multi-factor authentication: the mode and the grace period.
func TestMFAPolicySettings(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	admin := e.admin()

	// New organisations require MFA, with 7 days to set it up.
	p, err := e.st.MFAPolicy(ctx, e.org.ID)
	if err != nil || p.Mode != store.MFARequired || p.GracePeriodDays != 7 {
		t.Fatalf("new organisation: %+v %v", p, err)
	}

	for _, bad := range []map[string]any{{"mode": "sometimes"}, {"gracePeriodDays": 91}, {"gracePeriodDays": -1}} {
		if code, _ := e.do(admin, http.MethodPut, "/mfa-policy", bad); code != http.StatusUnprocessableEntity {
			t.Errorf("%v: %d", bad, code)
		}
	}

	code, raw := e.do(admin, http.MethodPut, "/mfa-policy", map[string]any{"mode": "custom", "gracePeriodDays": 30})
	var got store.MFAPolicy
	_ = json.Unmarshal(raw, &got)
	if code != http.StatusOK || got.Mode != "custom" || got.GracePeriodDays != 30 {
		t.Fatalf("save: %d %s", code, raw)
	}

	// Back to required: the grace period starts again from now.
	if _, err := e.st.DB.Exec(ctx, `UPDATE organisations SET mfa_required_since = now() - interval '60 days' WHERE id = $1`, e.org.ID); err != nil {
		t.Fatal(err)
	}
	e.do(admin, http.MethodPut, "/mfa-policy", map[string]any{"mode": "required"})
	var fresh bool
	_ = e.st.DB.QueryRow(ctx, `SELECT mfa_required_since > now() - interval '1 minute' FROM organisations WHERE id = $1`, e.org.ID).Scan(&fresh)
	if !fresh {
		t.Error("switching to required should restart the grace period")
	}

	// Needs "Set the password policy and MFA".
	helper := e.user("helper", "member")
	g := e.group("Helpdesk", store.PermViewUsers)
	_ = e.st.AddGroupMember(ctx, g.ID, helper.ID)
	if code, _ := e.do(helper, http.MethodPut, "/mfa-policy", map[string]any{"mode": "off"}); code != http.StatusForbidden {
		t.Errorf("without the permission: %d", code)
	}
}
