package adminapi

import (
	"testing"
	"time"

	"github.com/thekestongroup/id/internal/policy"
	"github.com/thekestongroup/id/internal/store"
)

func done(items []secItem) map[string]bool {
	m := map[string]bool{}
	for _, it := range items {
		m[it.ID] = it.Done
	}
	return m
}

func TestSecureScore(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-24*time.Hour), now.Add(-60*24*time.Hour)
	best := secFacts{MFAMode: store.MFARequired, Admins: 2, AdminsMFARequired: 2, AdminsWithMFA: 2,
		Policy: policy.Policy{MinLength: 12, MinDigits: 1}, AllowGuests: false, LogReviewedAt: &recent, Now: now}
	worst := secFacts{MFAMode: store.MFAOff, Admins: 1, Policy: policy.Policy{MinLength: 8}, AllowGuests: true,
		LogReviewedAt: &old, Now: now}

	total := 0
	for _, it := range evaluateSecurity(best) {
		total += it.Weight
	}
	if total != 100 {
		t.Errorf("weights add up to %d, want 100", total)
	}
	if s := secureScore(evaluateSecurity(best)); s != 100 {
		t.Errorf("everything done: %d", s)
	}
	if s := secureScore(evaluateSecurity(worst)); s != 0 {
		t.Errorf("nothing done: %d, %v", s, done(evaluateSecurity(worst)))
	}

	// The more that's done, the higher: each fix adds its weight.
	f := worst
	prev := secureScore(evaluateSecurity(f))
	for _, fix := range []func(*secFacts){
		func(f *secFacts) { f.AllowGuests = false },
		func(f *secFacts) { f.Policy = policy.Policy{MinLength: 12, MinDigits: 1} },
		func(f *secFacts) { f.Admins, f.AdminsMFARequired, f.AdminsWithMFA = 2, 0, 2 },
		func(f *secFacts) { f.AdminsMFARequired = 2 },
		func(f *secFacts) { f.MFAMode = store.MFARequired },
		func(f *secFacts) { f.LogReviewedAt = &recent },
	} {
		fix(&f)
		if s := secureScore(evaluateSecurity(f)); s <= prev {
			t.Errorf("score didn't rise: %d → %d", prev, s)
		} else {
			prev = s
		}
	}
	if prev != 100 {
		t.Errorf("after every fix: %d", prev)
	}
}

func TestChecklistItems(t *testing.T) {
	now := time.Now()
	f := secFacts{MFAMode: store.MFACustom, Admins: 1, AdminsMFARequired: 1, AdminsWithMFA: 0,
		Policy: policy.Policy{MinLength: 12}, AllowGuests: true, Now: now}
	d := done(evaluateSecurity(f))
	want := map[string]bool{itemMFAEveryone: false, itemMFAAdmins: true, itemPassword: false, itemTwoAdmins: false,
		itemAdminsMFA: false, itemGuestsOff: false, itemSignInReview: false}
	for id, w := range want {
		if d[id] != w {
			t.Errorf("%s: done=%v, want %v", id, d[id], w)
		}
	}
	// 12 characters and a number is "Recommended"; 11 or no number isn't.
	for _, tc := range []struct {
		p  policy.Policy
		ok bool
	}{{policy.Policy{MinLength: 12, MinDigits: 1}, true}, {policy.Policy{MinLength: 20, MinDigits: 2}, true},
		{policy.Policy{MinLength: 11, MinDigits: 1}, false}, {policy.Policy{MinLength: 12}, false}} {
		f.Policy = tc.p
		if got := done(evaluateSecurity(f))[itemPassword]; got != tc.ok {
			t.Errorf("%+v: %v", tc.p, got)
		}
	}
	// Advice items can't be applied; the settings can.
	for _, it := range evaluateSecurity(f) {
		advice := it.ID == itemTwoAdmins || it.ID == itemAdminsMFA || it.ID == itemSignInReview
		if it.CanApply == advice {
			t.Errorf("%s: canApply=%v", it.ID, it.CanApply)
		}
	}
	// A review older than 30 days no longer counts.
	old := now.Add(-31 * 24 * time.Hour)
	f.LogReviewedAt = &old
	if done(evaluateSecurity(f))[itemSignInReview] {
		t.Error("stale review counted")
	}
}

func TestPolicyWeakened(t *testing.T) {
	base := policy.Policy{MinLength: 12, MinDigits: 1, Blocked: []string{"school"}}
	for name, tc := range map[string]struct {
		after policy.Policy
		want  bool
	}{
		"same":         {base, false},
		"stricter":     {policy.Policy{MinLength: 14, MinDigits: 2, MinSpecial: 1, Blocked: []string{"school", "x"}}, false},
		"shorter":      {policy.Policy{MinLength: 10, MinDigits: 1, Blocked: []string{"school"}}, true},
		"fewer digits": {policy.Policy{MinLength: 12, Blocked: []string{"school"}}, true},
		"unblocked":    {policy.Policy{MinLength: 12, MinDigits: 1}, true},
	} {
		if got := policyWeakened(base, tc.after); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
