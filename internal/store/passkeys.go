package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/thekestongroup/id/internal/secret"
)

// ── Passkeys and security keys (WebAuthn) ───────────────────────────────

type Passkey struct {
	ID         string
	UserID     string
	Name       string
	Credential webauthn.Credential
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

const passkeyColumns = `id, user_id, name, credential, created_at, last_used_at`

func scanPasskey(row pgx.Row) (*Passkey, error) {
	var p Passkey
	var raw []byte
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &raw, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return nil, notFound(err)
	}
	if err := json.Unmarshal(raw, &p.Credential); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) PasskeysForUser(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE user_id = $1 ORDER BY created_at`,
		userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Passkey, error) {
		p, err := scanPasskey(r)
		if err != nil {
			return Passkey{}, err
		}
		return *p, nil
	})
}

// PasskeyByCredentialID finds the passkey an authenticator used.
func (s *Store) PasskeyByCredentialID(ctx context.Context, credentialID []byte) (*Passkey, error) {
	return scanPasskey(s.DB.QueryRow(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE credential_id = $1`,
		credentialID))
}

func (s *Store) AddPasskey(ctx context.Context, userID, name string, cred *webauthn.Credential) (*Passkey, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	return scanPasskey(s.DB.QueryRow(ctx, `INSERT INTO passkeys (user_id, credential_id, name, credential)
		VALUES ($1, $2, $3, $4) RETURNING `+passkeyColumns, userID, cred.ID, name, raw))
}

// RenamePasskey: ErrNotFound if it isn't one of theirs.
func (s *Store) RenamePasskey(ctx context.Context, userID, id, name string) (*Passkey, error) {
	return scanPasskey(s.DB.QueryRow(ctx, `UPDATE passkeys SET name = $3 WHERE id = $2 AND user_id = $1
		RETURNING `+passkeyColumns, userID, id, name))
}

// DeletePasskey: ErrNotFound if it isn't one of theirs.
func (s *Store) DeletePasskey(ctx context.Context, userID, id string) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM passkeys WHERE id = $2 AND user_id = $1`, userID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeletePasskeys removes all of someone's passkeys (an admin turning off
// their MFA), returning how many there were.
func (s *Store) DeletePasskeys(ctx context.Context, userID string) (int, error) {
	tag, err := s.DB.Exec(ctx, `DELETE FROM passkeys WHERE user_id = $1`, userID)
	return int(tag.RowsAffected()), err
}

// PasskeyUsed records a sign-in with a passkey: its new sign count and
// flags, and when.
func (s *Store) PasskeyUsed(ctx context.Context, id string, cred *webauthn.Credential) error {
	raw, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `UPDATE passkeys SET credential = $2, last_used_at = now() WHERE id = $1`, id, raw)
	return err
}

func (s *Store) PasskeyCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.DB.QueryRow(ctx, `SELECT count(*) FROM passkeys WHERE user_id = $1`, userID).Scan(&n)
	return n, err
}

// PasskeyCounts: how many passkeys each user in an organisation has (users
// with none aren't in the map).
func (s *Store) PasskeyCounts(ctx context.Context, orgID string) (map[string]int, error) {
	rows, err := s.DB.Query(ctx, `SELECT p.user_id, count(*) FROM passkeys p JOIN users u ON u.id = p.user_id
		WHERE u.organisation_id = $1 GROUP BY p.user_id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// HasMFA: an authenticator app, or at least one passkey or security key.
// Someone with MFA is asked for it after their password.
func (s *Store) HasMFA(ctx context.Context, u *User) (bool, error) {
	if u.TOTPEnabled {
		return true, nil
	}
	n, err := s.PasskeyCount(ctx, u.ID)
	return n > 0, err
}

// ── WebAuthn ceremonies ─────────────────────────────────────────────────

// Ceremony purposes.
const (
	CeremonyRegister = "register"
	CeremonyMFA      = "mfa"
	CeremonySignIn   = "sign-in"
)

// StartCeremony keeps a ceremony's challenge (go-webauthn's SessionData)
// until the browser answers, and returns the token it sends back with the
// answer. userID and sessionID are who it's for ("" for neither).
func (s *Store) StartCeremony(ctx context.Context, purpose, userID, sessionID string, data *webauthn.SessionData,
	ttl time.Duration) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	// Old ones go as new ones arrive.
	if _, err := s.DB.Exec(ctx, `DELETE FROM webauthn_ceremonies WHERE expires_at < now()`); err != nil {
		return "", err
	}
	token := secret.Token()
	_, err = s.DB.Exec(ctx, `INSERT INTO webauthn_ceremonies (id, purpose, user_id, session_id, data, expires_at)
		VALUES ($1, $2, $3, $4, $5, now() + $6::interval)`,
		secret.Hash(token), purpose, nullIfEmpty(userID), nullIfEmpty(sessionID), raw, ttl)
	return token, err
}

// TakeCeremony finds a live ceremony for this purpose, user and session,
// and removes it, so each challenge is answered once. ErrNotFound if
// there's none.
func (s *Store) TakeCeremony(ctx context.Context, token, purpose, userID, sessionID string) (*webauthn.SessionData,
	error) {
	var raw []byte
	err := s.DB.QueryRow(ctx, `DELETE FROM webauthn_ceremonies
		WHERE id = $1 AND purpose = $2 AND expires_at > now()
			AND user_id IS NOT DISTINCT FROM $3 AND session_id IS NOT DISTINCT FROM $4
		RETURNING data`, secret.Hash(token), purpose, nullIfEmpty(userID), nullIfEmpty(sessionID)).Scan(&raw)
	if err != nil {
		return nil, notFound(err)
	}
	var data webauthn.SessionData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
