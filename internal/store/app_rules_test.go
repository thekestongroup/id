package store

import "testing"

func TestResolveAppMode(t *testing.T) {
	const me = "u1"
	in := []string{"teachers", "office"}
	rule := func(mode string, mutate func(*AppRule)) AppRule {
		r := AppRule{Name: mode, Enabled: true, Mode: mode, Users: []string{}, Groups: []string{}, IPRanges: []string{}}
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	group := func(g string) func(*AppRule) { return func(r *AppRule) { r.Groups = []string{g} } }

	tests := []struct {
		name  string
		def   string
		rules []AppRule
		ip    string
		want  string
	}{
		{"no rules: the default", AppEnabled, nil, "", AppEnabled},
		{"no rules, no default: nothing", "", nil, "", ""},
		{"a rule beats the default", AppEnabled, []AppRule{rule(AppDisabled, group("teachers"))}, "", AppDisabled},
		{"a rule about another group is skipped", AppForced, []AppRule{rule(AppDisabled, group("pupils"))}, "", AppForced},
		{"first match wins", "", []AppRule{
			rule(AppForced, group("office")), rule(AppDisabled, group("teachers")),
		}, "", AppForced},
		{"order matters", "", []AppRule{
			rule(AppDisabled, group("teachers")), rule(AppForced, group("office")),
		}, "", AppDisabled},
		// What the migration of per-group settings relies on: Disabled,
		// then Forced, then Enabled, so the old precedence still holds.
		{"migrated: disabled beats forced beats enabled", AppEnabled, []AppRule{
			rule(AppDisabled, group("pupils")), rule(AppForced, group("office")), rule(AppEnabled, group("teachers")),
		}, "", AppForced},
		{"a turned-off rule is skipped", AppEnabled, []AppRule{
			rule(AppDisabled, func(r *AppRule) { r.Groups = []string{"teachers"}; r.Enabled = false }),
		}, "", AppEnabled},
		{"a rule about a user", "", []AppRule{rule(AppDisabled, func(r *AppRule) { r.Users = []string{me} })}, "", AppDisabled},
		{"a rule about another user", AppForced, []AppRule{rule(AppDisabled, func(r *AppRule) { r.Users = []string{"u2"} })}, "", AppForced},
		{"user and group must both match", AppForced, []AppRule{
			rule(AppDisabled, func(r *AppRule) { r.Users = []string{me}; r.Groups = []string{"pupils"} }),
		}, "", AppForced},
		{"no conditions: everyone", "", []AppRule{rule(AppDisabled, nil)}, "", AppDisabled},
		{"in the range", AppForced, []AppRule{rule(AppDisabled, func(r *AppRule) { r.IPRanges = []string{"10.0.0.0/8"} })},
			"10.1.2.3", AppDisabled},
		{"outside the range", AppForced, []AppRule{rule(AppDisabled, func(r *AppRule) { r.IPRanges = []string{"10.0.0.0/8"} })},
			"192.0.2.1", AppForced},
		{"an unknown address never matches a range", AppForced, []AppRule{
			rule(AppDisabled, func(r *AppRule) { r.IPRanges = []string{"10.0.0.0/8"} }),
		}, "", AppForced},
		{"a mapped IPv4 address", AppForced, []AppRule{rule(AppDisabled, func(r *AppRule) { r.IPRanges = []string{"10.0.0.0/8"} })},
			"::ffff:10.1.2.3", AppDisabled},
		{"group, then a catch-all", AppEnabled, []AppRule{
			rule(AppForced, group("office")), rule(AppDisabled, nil),
		}, "", AppForced},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveAppMode(tt.def, tt.rules, me, in, tt.ip); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
