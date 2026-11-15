package policy

import "testing"

func TestGenerate(t *testing.T) {
	for _, p := range []Policy{{}, {MinLength: 30, MinUppercase: 5, MinLowercase: 5, MinDigits: 5, MinSpecial: 5},
		{MinSpecial: 20}} {
		seen := map[string]bool{}
		for range 50 {
			pw := p.Generate("j.smith")
			if failed := p.Check(pw, "j.smith"); len(failed) > 0 {
				t.Fatalf("%+v: %q fails %v", p, pw, failed)
			}
			if seen[pw] {
				t.Fatalf("%q generated twice", pw)
			}
			seen[pw] = true
		}
	}
}
