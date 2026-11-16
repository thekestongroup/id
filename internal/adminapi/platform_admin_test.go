package adminapi

import (
	"testing"

	"github.com/thekestongroup/id/internal/store"
)

func TestPlatformAdminProblem(t *testing.T) {
	platform := &store.Organisation{IsPlatform: true}
	other := &store.Organisation{}
	tkg := &store.User{ID: "a", PlatformAdmin: true, Role: "global_admin"}
	global := &store.User{ID: "b", Role: "global_admin"}
	target := &store.User{ID: "c", Role: "global_admin"}

	for _, c := range []struct {
		name   string
		org    *store.Organisation
		by     *store.User
		target *store.User
		role   string
		on     bool
		bad    bool
	}{
		{"TKG Admin makes one", platform, tkg, target, "global_admin", true, false},
		{"creating one", platform, tkg, nil, "global_admin", true, false},
		{"removes another", platform, tkg, target, "global_admin", false, false},
		{"global admin can't", platform, global, target, "global_admin", true, true},
		{"not outside the platform organisation", other, tkg, target, "global_admin", true, true},
		{"needs global admin", platform, tkg, target, "member", true, true},
		{"not on themselves", platform, tkg, tkg, "global_admin", false, true},
	} {
		if got := platformAdminProblem(c.org, c.by, c.target, c.role, c.on); (got != "") != c.bad {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}
