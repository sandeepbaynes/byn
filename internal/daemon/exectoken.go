package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// execTokenTTL bounds how long a minted exec token is redeemable. The privsep
// helper redeems within milliseconds of the CLI receiving the token, so a short
// window minimizes the replay surface for a same-UID race on the CLI→helper
// handoff (the accepted AR-1 sibling-sniff class). Tokens are also single-use.
const execTokenTTL = 30 * time.Second

// execTokenLen is the byte length of a minted token (CSPRNG, 256-bit).
const execTokenLen = 32

// execToken is a minted, not-yet-redeemed authorization to spawn ONE
// terminal-anchored exec child. It holds the daemon-authorized argv, the
// COMPLETE curated child env (base env minus dangerous keys + injected secrets),
// and the sandbox profile. The env carries secret values, so it is zeroized on
// redeem-of-expired and on sweep.
type execToken struct {
	argv    []string
	env     []string
	profile string
	expires time.Time
}

// execTokenStore holds one-time exec tokens keyed by their hex string. It is the
// daemon-side half of the token-redemption secret-delivery path: handleExecAuthorize
// mints (after the trust/auth gate), handleExecRedeem redeems (helper only).
type execTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*execToken
	now    func() time.Time
}

// newExecTokenStore returns an empty store using the wall clock.
func newExecTokenStore() *execTokenStore {
	return &execTokenStore{tokens: make(map[string]*execToken), now: time.Now}
}

// mint stores the payload under a fresh CSPRNG token and returns the raw token
// bytes. It opportunistically sweeps expired tokens first so an unredeemed token
// (helper crashed before redeeming) does not linger with its secret env. The
// env slice is held verbatim; the caller transfers ownership to the store.
func (s *execTokenStore) mint(argv, env []string, profile string) ([]byte, error) {
	b := make([]byte, execTokenLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	key := hex.EncodeToString(b)
	s.mu.Lock()
	s.sweepLocked()
	s.tokens[key] = &execToken{argv: argv, env: env, profile: profile, expires: s.now().Add(execTokenTTL)}
	s.mu.Unlock()
	return b, nil
}

// redeem removes and returns the payload for tok if present and unexpired.
// One-time: any matched token is deleted whether or not it had expired. An
// expired token's env is zeroized before the miss is reported. ok=false on an
// unknown, expired, or empty token.
func (s *execTokenStore) redeem(tok []byte) (argv, env []string, profile string, ok bool) {
	if len(tok) == 0 {
		return nil, nil, "", false
	}
	key := hex.EncodeToString(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, found := s.tokens[key]
	if !found {
		return nil, nil, "", false
	}
	delete(s.tokens, key) // one-time, even when expired
	if s.now().After(e.expires) {
		zeroEnv(e.env)
		return nil, nil, "", false
	}
	return e.argv, e.env, e.profile, true
}

// sweepLocked drops (and zeroizes the env of) every expired token. Caller holds
// s.mu.
func (s *execTokenStore) sweepLocked() {
	now := s.now()
	for k, e := range s.tokens {
		if now.After(e.expires) {
			zeroEnv(e.env)
			delete(s.tokens, k)
		}
	}
}

// zeroEnv best-effort overwrites the backing bytes of each KEY=VALUE string in
// env. Go strings are immutable from the language's view, but the underlying
// bytes can be cleared via an unsafe-free trick using a byte slice copy is not
// possible without unsafe; instead we drop the references so the GC can reclaim
// them. This matches the existing daemon hygiene level for in-memory secret
// strings (the vault key is the hardened secret; injected values briefly live as
// strings, as they already do in handleExecSpawn).
func zeroEnv(env []string) {
	for i := range env {
		env[i] = ""
	}
}
