package daemon

// sessions.go — NU-3 Task 1: daemon session store.
//
// A session binds key-access to the terminal/surface that ran vault.unlock,
// rather than granting blanket same-UID access for the daemon's lifetime.
//
// # Design decisions recorded here
//
// ## TTYDev strategy (NU-3 Task 3)
//
// Sessions bind to the controlling terminal device number (tty_nr / Tdev) of
// the socket peer that unlocked the vault, obtained via peerTTYDev(peerPID)
// from the platform-specific procinfo file.  TTYDev was chosen because:
//   - The whole terminal session (shell + children) shares the same controlling
//     tty device, so any process in the same terminal window can use the session
//     without re-unlocking.
//   - The CLI client can independently derive the same value by stat-ing
//     /dev/tty, enabling it to scope session files per-TTY on disk
//     (cmd/byn/sessions.go).
//   - Cross-platform: Darwin reads Eproc.Tdev from kern.proc.pid sysctl;
//     Linux reads tty_nr from /proc/<pid>/stat.
//
// ## TTYDev-0 degradation
//
// Portal requests (browser → in-process Dispatch) have no socket peer, so no
// TTYDev is derivable.  Portal sessions are minted with ttyDev=0, which signals
// "uid-only binding" — the session remains valid for any uid-matching caller.
// This is intentional: the portal authenticates through its long-lived token
// (verified outside this session layer), and the portal process is always
// co-located with the daemon (same PID/UID, not an independent terminal).
//
// SOCKET callers with a missing TTYDev (peerTTYDev returned 0 — process has no
// controlling terminal) also land in ttyDev=0 at mint time and degrade to
// uid-only binding.  A warning is logged at mint so operators can track this
// path.  (A session minted with ttyDev=0 for a socket caller accepts any
// subsequent socket caller with the same uid — tolerated because the socket
// is mode 0600 and already uid-gated at the connection layer.)
//
// ## Token timing
//
// Tokens are 32 random bytes hex-encoded (64-char string).  Map-key lookup
// timing is not a meaningful attack surface for 256-bit random tokens: the
// comparison terminates in constant time relative to the keyspace size, and
// the keyspace (2^256) dwarfs any realistic guessing budget.
//
// ## Config keys
//
//	[security]
//	session_ttl  = "12h"   # absolute TTL after mint; 0 ⇒ never expires
//	session_idle = "0s"    # sliding idle window; 0 ⇒ inherit daemon idle_timeout

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
)

// session is one live session record inside the sessionStore.
type session struct {
	// Vault is the vault name this session was minted for.
	Vault string
	// Surface distinguishes the unlock surface: "cli" (Unix socket) or "portal" (in-process browser).
	Surface string
	// UID is the effective UID of the peer that minted the session.
	UID uint32
	// TTYDev is the controlling terminal device number of the minting socket peer.
	// 0 means "uid-only binding" — see package-level comment above.
	TTYDev int32
	// CreatedAt is the wall-clock time the session was minted.
	CreatedAt time.Time
	// LastUsed is the wall-clock time of the most recent successful validate call.
	// Updated on every successful validate (sliding window for idle expiry).
	LastUsed time.Time
}

// sessionStore is a mutex-guarded, TTL+idle-expiry map of session tokens.
// The zero value is NOT usable; call newSessionStore.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session // token (hex) → session
	ttl      time.Duration       // absolute TTL after CreatedAt; 0 = no abs-TTL limit
	idle     time.Duration       // idle window after LastUsed; 0 = no idle limit
}

// newSessionStore constructs a sessionStore with the given TTL and idle
// durations.  0 values disable the respective expiry check.
func newSessionStore(ttl, idle time.Duration) *sessionStore {
	return &sessionStore{
		sessions: make(map[string]*session),
		ttl:      ttl,
		idle:     idle,
	}
}

// mint creates a new session and returns the hex-encoded token.
// ttyDev=0 signals uid-only binding (no terminal constraint); the caller
// must already have decided whether to warn (handleConn does this at socket
// accept time).
func (s *sessionStore) mint(vault, surface string, uid uint32, ttyDev int32, now time.Time) string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failure is catastrophic — panic so tests see it immediately.
		panic(fmt.Sprintf("sessions: rand.Read: %v", err))
	}
	token := hex.EncodeToString(buf[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[token] = &session{
		Vault:     vault,
		Surface:   surface,
		UID:       uid,
		TTYDev:    ttyDev,
		CreatedAt: now,
		LastUsed:  now,
	}
	return token
}

// validate checks whether token is a live session for the given vault and
// caller identity.  It returns true and updates LastUsed on success.
//
// Binding rules:
//   - vault must match the session's Vault.
//   - uid must always match.
//   - ttyDev is checked only when the stored ttyDev != 0 (a ttyDev=0 session
//     accepts any ttyDev from a matching-uid caller — see package comment).
func (s *sessionStore) validate(token, vault string, uid uint32, ttyDev int32, now time.Time) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return false
	}
	// Vault binding.
	if sess.Vault != vault {
		return false
	}
	// UID binding — always enforced.
	if sess.UID != uid {
		return false
	}
	// TTYDev binding — only when stored ttyDev is non-zero.
	if sess.TTYDev != 0 && sess.TTYDev != ttyDev {
		return false
	}
	// Absolute TTL check.
	if s.ttl > 0 && now.Sub(sess.CreatedAt) >= s.ttl {
		delete(s.sessions, token)
		return false
	}
	// Idle window check (sliding).
	if s.idle > 0 && now.Sub(sess.LastUsed) >= s.idle {
		delete(s.sessions, token)
		return false
	}
	// Valid — slide LastUsed.
	sess.LastUsed = now
	return true
}

// endVault invalidates all sessions for the named vault (called on lock/shutdown).
// It returns the Surface value of every session that was ended, one entry per
// ended session (duplicates possible). Callers use this to emit session.end
// audit events without inspecting token values.
func (s *sessionStore) endVault(vault string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var surfaces []string
	for token, sess := range s.sessions {
		if sess.Vault == vault {
			surfaces = append(surfaces, sess.Surface)
			delete(s.sessions, token)
		}
	}
	return surfaces
}

// endToken invalidates a single session token and returns the vault name and
// surface of the ended session (both "" when the token was absent).  A no-op
// when the token is absent (idempotent).  Callers use the returned vault name
// to emit the session.end audit event against the correct vault log.
func (s *sessionStore) endToken(token string) (vaultName, surface string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[token]; ok {
		vaultName = sess.Vault
		surface = sess.Surface
		delete(s.sessions, token)
	}
	return vaultName, surface
}

// sweep removes all expired sessions (absolute-TTL and idle) and returns the
// count removed.  Should be called periodically by the daemon's idle janitor.
func (s *sessionStore) sweep(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for token, sess := range s.sessions {
		if s.ttl > 0 && now.Sub(sess.CreatedAt) >= s.ttl {
			delete(s.sessions, token)
			removed++
			continue
		}
		if s.idle > 0 && now.Sub(sess.LastUsed) >= s.idle {
			delete(s.sessions, token)
			removed++
		}
	}
	return removed
}

// mintSessionForSocket mints a new session from a socket caller, deriving the
// TTYDev from the peer PID.  If TTYDev derivation fails (process has no
// controlling terminal) the session degrades to uid-only binding (ttyDev=0)
// and a warning is logged.
func (d *Daemon) mintSessionForSocket(vault string, uid uint32, pid int, now time.Time) string {
	ttyDev := peerTTYDev(pid)
	if ttyDev == 0 && pid > 0 {
		log.Printf("byn: session mint: could not determine TTYDev for pid %d (vault=%s uid=%d); "+
			"session degrades to uid-only binding", pid, vault, uid)
	}
	d.auditSession("session.mint", vault, "cli")
	return d.sessions.mint(vault, "cli", uid, ttyDev, now)
}

// mintSessionForPortal mints a session for a portal (browser/in-process)
// unlock.  Portal sessions always use ttyDev=0 (uid-only binding) because no
// socket peer is available — see package-level comment.
func (d *Daemon) mintSessionForPortal(vault string, now time.Time) string {
	uid := d.ownerUID
	d.auditSession("session.mint", vault, "portal")
	return d.sessions.mint(vault, "portal", uid, 0, now)
}

// sessionInfo returns whether token is a live session for the given vault/uid/ttyDev
// (read-only — does NOT slide LastUsed) and its expiry time (nil if no abs-TTL).
// Used by handleStatus to populate SessionActive + SessionExpiresAt on VaultSummary.
func (s *sessionStore) sessionInfo(token, vault string, uid uint32, ttyDev int32, now time.Time) (active bool, expiresAt *time.Time) {
	if token == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return false, nil
	}
	if sess.Vault != vault {
		return false, nil
	}
	if sess.UID != uid {
		return false, nil
	}
	if sess.TTYDev != 0 && sess.TTYDev != ttyDev {
		return false, nil
	}
	if s.ttl > 0 && now.Sub(sess.CreatedAt) >= s.ttl {
		return false, nil
	}
	if s.idle > 0 && now.Sub(sess.LastUsed) >= s.idle {
		return false, nil
	}
	var exp *time.Time
	if s.ttl > 0 {
		t := sess.CreatedAt.Add(s.ttl)
		exp = &t
	}
	if s.idle > 0 {
		idleExp := sess.LastUsed.Add(s.idle)
		if exp == nil || idleExp.Before(*exp) {
			exp = &idleExp
		}
	}
	return true, exp
}

// auditSession emits a session lifecycle audit event (mint-only; end events
// are emitted directly by the caller so the correct vault name and ctx are
// used).  The token value is never included — only vault + surface.
func (d *Daemon) auditSession(op, vault, surface string) {
	// Use handlerCtx (daemon root context) for session-lifecycle events; these
	// are daemon-internal and not tied to a single request context.
	ctx := d.handlerCtx()
	d.auditEmit(ctx, vault, audit.Event{
		Op:            op,
		Outcome:       audit.OutcomeOK,
		CallerSurface: surface,
	})
}
