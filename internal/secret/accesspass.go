package secret

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// Temporary access pass codes look like "K7Q2-M9XD-4HTR-PWZB": 16
// characters (about 79 bits) from capitals and digits that can't be mistaken
// for each other. Only Hash(NormaliseAccessPass(code)) is kept.
const accessPassAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// NewAccessPass makes a code (to show once) and the hash to keep.
func NewAccessPass() (code, hash string) {
	raw := make([]byte, 16)
	max := big.NewInt(int64(len(accessPassAlphabet)))
	for i := range raw {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		raw[i] = accessPassAlphabet[n.Int64()]
	}
	s := string(raw)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16], Hash(s)
}

// NormaliseAccessPass: a code as typed, as it's hashed (capitals, without
// spaces or dashes).
func NormaliseAccessPass(code string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(code)))
}
