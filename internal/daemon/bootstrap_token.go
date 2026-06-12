package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// bootstrapTokenTTL is the lifetime of a one-time portal bootstrap token.
// Short enough that a ps-captured value is useless by the time an attacker
// could act on it. 5s is generous for a local browser open while being
// tight enough that a captured token is stale before an attacker can act.
const bootstrapTokenTTL = 5 * time.Second

// bootstrapToken is one pending bootstrap exchange.
type bootstrapToken struct {
	expires time.Time
}

// bootstrapTokens is an in-memory map of pending one-time portal bootstrap
// tokens, keyed by the hex token string. Each token is minted by the daemon
// on behalf of `byn web` (via the UID-gated Unix socket) and consumed exactly
// once by the SPA at POST /api/session/bootstrap.
type bootstrapTokens struct {
	mu sync.Mutex
	m  map[string]bootstrapToken
}

func newBootstrapTokens() *bootstrapTokens {
	return &bootstrapTokens{m: make(map[string]bootstrapToken)}
}

// mint generates a fresh bootstrap token, stores it with a 5s TTL, and
// returns its hex string. Expired entries are pruned on each mint.
func (b *bootstrapTokens) mint(now time.Time) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf[:])
	b.mu.Lock()
	defer b.mu.Unlock()
	// Prune expired tokens.
	for k, t := range b.m {
		if now.After(t.expires) {
			delete(b.m, k)
		}
	}
	b.m[id] = bootstrapToken{expires: now.Add(bootstrapTokenTTL)}
	return id, nil
}

// consume removes the token and returns true only if it existed and was
// unexpired. Single-use — calling twice with the same token returns false
// on the second call.
func (b *bootstrapTokens) consume(token string, now time.Time) bool {
	if token == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.m[token]
	if !ok {
		return false
	}
	delete(b.m, token)
	return !now.After(t.expires)
}
