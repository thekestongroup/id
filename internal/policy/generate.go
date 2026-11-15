package policy

import (
	"crypto/rand"
	"math/big"
)

// Characters for generated passwords, leaving out ones that are easy to
// misread (0 O o, 1 l I).
const (
	genUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	genLower   = "abcdefghijkmnpqrstuvwxyz"
	genDigits  = "23456789"
	genSpecial = "!#%+=?@"
)

func pick(set string) byte {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		panic(err) // crypto/rand doesn't fail on supported platforms
	}
	return set[n.Int64()]
}

// Generate makes a random password that meets the policy (at least 16
// characters, with every kind it asks for). avoid is as for Check.
func (p Policy) Generate(avoid ...string) string {
	p = p.Normalise()
	length := max(p.MinLength, 16, p.MinUppercase+p.MinLowercase+p.MinDigits+p.MinSpecial)
	for {
		var b []byte
		for set, n := range map[string]int{genUpper: max(p.MinUppercase, 1), genLower: max(p.MinLowercase, 1),
			genDigits: max(p.MinDigits, 1), genSpecial: p.MinSpecial} {
			for range n {
				b = append(b, pick(set))
			}
		}
		all := genUpper + genLower + genDigits
		if p.MinSpecial > 0 {
			all += genSpecial
		}
		for len(b) < length {
			b = append(b, pick(all))
		}
		// Shuffle, so the required kinds aren't always at the start.
		for i := len(b) - 1; i > 0; i-- {
			j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
			b[i], b[j.Int64()] = b[j.Int64()], b[i]
		}
		if pw := string(b); len(p.Check(pw, avoid...)) == 0 {
			return pw
		}
	}
}
