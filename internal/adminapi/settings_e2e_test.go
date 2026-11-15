//go:build e2e

package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Settings → Username format: first.last unless changed; only known
// formats; profile editing left alone when only the format changes.
func TestUsernameFormat(t *testing.T) {
	e := setup(t)
	admin := e.admin()
	if e.org.UsernameFormat != "{first}.{last}" {
		t.Fatalf("default: %q", e.org.UsernameFormat)
	}
	if code, _ := e.do(admin, http.MethodPut, "/settings", map[string]any{"usernameFormat": "nickname"}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown format: %d", code)
	}
	e.do(admin, http.MethodPut, "/settings", map[string]any{"profileEditing": map[string]bool{"name": true}})
	code, raw := e.do(admin, http.MethodPut, "/settings", map[string]any{"usernameFormat": "{first:1}.{last}"})
	var out struct {
		UsernameFormat string
		ProfileEditing struct{ Name bool }
	}
	_ = json.Unmarshal(raw, &out)
	if code != http.StatusOK || out.UsernameFormat != "{first:1}.{last}" || !out.ProfileEditing.Name {
		t.Fatalf("save: %d %s", code, raw)
	}
	org, _ := e.st.OrganisationByID(context.Background(), e.org.ID)
	if org.UsernameFormat != "{first:1}.{last}" || !org.ProfileEditing.Name {
		t.Errorf("stored: %+v", org)
	}
}
