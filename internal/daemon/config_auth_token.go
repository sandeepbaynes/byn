package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// configAuthTokenTTL bounds the unused window of a one-time config-WRITE token.
// It only has to bridge the CLI→browser handoff: the owner runs `byn config-auth`,
// copies the printed code, and pastes it into the settings panel. 60s is generous
// for that paste while staying short-lived; the token is single-use and mintable
// only AFTER `sudo -v` succeeds, over the owner-UID socket, so a captured-but-
// unused value is near worthless.
const configAuthTokenTTL = 60 * time.Second

// configAuthTokens is an in-memory store of single-use tokens that each authorize
// exactly ONE config write. Minted by `byn config-auth` (after the CLI proves sudo
// via PAM) over the UID-gated socket, consumed once at POST /api/config. This is
// the gate that stops a same-UID process or a plain portal session from changing
// security-critical settings (e.g. [security] privsep): only a fresh, sudo-verified
// token can write config. Reads are NOT gated (config holds settings, not secrets).
type configAuthTokens struct {
	mu sync.Mutex
	m  map[string]time.Time // token → expiry
}

func newConfigAuthTokens() *configAuthTokens {
	return &configAuthTokens{m: make(map[string]time.Time)}
}

// mint generates a fresh single-use config-write token with a configAuthTokenTTL
// lifetime and returns its hex string. Expired entries are pruned on each mint.
func (c *configAuthTokens) mint(now time.Time) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.m {
		if now.After(exp) {
			delete(c.m, k)
		}
	}
	c.m[id] = now.Add(configAuthTokenTTL)
	return id, nil
}

// consume removes the token and returns true only if it existed and was
// unexpired. Single-use: a second call with the same token returns false.
func (c *configAuthTokens) consume(token string, now time.Time) bool {
	if token == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[token]
	if !ok {
		return false
	}
	delete(c.m, token)
	return !now.After(exp)
}
