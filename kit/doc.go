// Package kit is what every Keston API shares, so each product (Keston ID,
// Keston Work, Keston Learn…) runs its own API to one standard without
// depending on the others:
//
//   - auth: checks Keston ID access tokens locally (signed JWTs, against
//     Keston ID's published keys) and gives handlers the caller: who they
//     are, their organisation and their permissions.
//   - apierr: the error format every API returns.
//
// It deliberately depends on nothing but go-jose, so a product can import it
// without pulling in Keston ID.
package kit
