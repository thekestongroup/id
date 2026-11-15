package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// RemoteKeys fetches Keston ID's published signing keys (its JWKS), caching
// them, and fetches again when a token is signed with a key it doesn't know
// yet (at most every 30 seconds). Keys rotate every 90 days, with the old
// key kept for a while, so a cached set keeps working through rotation.
type RemoteKeys struct {
	URL    string
	Client *http.Client
	// How long a fetched set is used before fetching again.
	TTL time.Duration

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetched time.Time
}

// NewRemoteKeys reads keys from issuer's /keys (Keston ID's JWKS address).
func NewRemoteKeys(issuer string) *RemoteKeys {
	return &RemoteKeys{URL: strings.TrimSuffix(issuer, "/") + "/keys",
		Client: &http.Client{Timeout: 5 * time.Second}, TTL: time.Hour}
}

func (k *RemoteKeys) Keys(ctx context.Context) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys != nil && time.Since(k.fetched) < k.TTL {
		return k.keys, nil
	}
	if err := k.fetch(ctx); err != nil && k.keys == nil {
		return nil, err
	}
	// On failure, keep using the keys we have.
	return k.keys, nil
}

// Refresh fetches again now (rate limited), for a key we don't know yet.
func (k *RemoteKeys) Refresh(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if time.Since(k.fetched) < 30*time.Second {
		return nil
	}
	return k.fetch(ctx)
}

func (k *RemoteKeys) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.URL, nil)
	if err != nil {
		return err
	}
	res, err := k.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("keys: %s returned %s", k.URL, res.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	k.keys, k.fetched = set.Keys, time.Now()
	return nil
}

// StaticKeys is a fixed set (for tests, or Keston ID checking its own).
type StaticKeys []jose.JSONWebKey

func (s StaticKeys) Keys(context.Context) ([]jose.JSONWebKey, error) { return s, nil }

// KeysFunc adapts a function to KeySet.
type KeysFunc func(ctx context.Context) ([]jose.JSONWebKey, error)

func (f KeysFunc) Keys(ctx context.Context) ([]jose.JSONWebKey, error) { return f(ctx) }
