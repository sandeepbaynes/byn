package ui

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// sessionCookie names the portal's passkey session cookie.
const sessionCookie = "byn_passkey_session"

// sessionTTL bounds how long a passkey-authenticated portal session lasts.
const sessionTTL = 30 * time.Minute

// pkSession is one authenticated portal session.
type pkSession struct {
	vault   string
	expires time.Time
}

// pkSessions is an in-memory, TTL'd store of passkey-authenticated portal
// sessions. It lives in the portal (HTTP layer) because sessions are a cookie
// concept; the daemon owns the ceremony verification that gates issuance.
type pkSessions struct {
	mu sync.Mutex
	m  map[string]pkSession
}

func newPKSessions() *pkSessions { return &pkSessions{m: make(map[string]pkSession)} }

// issue mints a session token for vaultName.
func (s *pkSessions) issue(vaultName string, now time.Time) (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	s.m[tok] = pkSession{vault: vaultName, expires: now.Add(sessionTTL)}
	return tok, nil
}

// lookup returns the session's vault and whether the token is valid + unexpired.
func (s *pkSessions) lookup(tok string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[tok]
	if !ok || now.After(sess.expires) {
		return "", false
	}
	return sess.vault, true
}

func (s *pkSessions) gcLocked(now time.Time) {
	for t, sess := range s.m {
		if now.After(sess.expires) {
			delete(s.m, t)
		}
	}
}

func defaultVault(name string) string {
	if name == "" {
		return "default"
	}
	return name
}

// POST /api/passkey/register/begin {vault} → {ceremony_id, options}.
// Enrollment requires the vault unlocked; the daemon enforces that.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
	}
	_ = decodeJSON(r, &body)
	var resp ipc.PasskeyRegisterBeginResp
	if !s.run(w, r, ipc.OpPasskeyRegisterBegin, ipc.PasskeyRegisterBeginReq{Vault: body.Vault}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/passkey/register/finish {vault, ceremony_id, response, label}.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault      string          `json:"vault"`
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
		Label      string          `json:"label"`
		KEK        []byte          `json:"kek"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var resp ipc.PasskeyRegisterFinishResp
	if !s.run(w, r, ipc.OpPasskeyRegisterFinish, ipc.PasskeyRegisterFinishReq{
		Vault: body.Vault, CeremonyID: body.CeremonyID, Response: body.Response, Label: body.Label, KEK: body.KEK,
	}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/passkey/auth/begin {vault} → {ceremony_id, options}.
func (s *Server) handlePasskeyAuthBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
	}
	_ = decodeJSON(r, &body)
	var resp ipc.PasskeyAuthBeginResp
	if !s.run(w, r, ipc.OpPasskeyAuthBegin, ipc.PasskeyAuthBeginReq{Vault: body.Vault}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/passkey/auth/finish {vault, ceremony_id, response}. On a verified
// assertion the daemon confirms the credential; the portal then issues a
// session cookie. (A-auth.2 will also unlock the vault here.)
func (s *Server) handlePasskeyAuthFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault      string          `json:"vault"`
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
		KEK        []byte          `json:"kek"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var resp ipc.PasskeyAuthFinishResp
	if !s.run(w, r, ipc.OpPasskeyAuthFinish, ipc.PasskeyAuthFinishReq{
		Vault: body.Vault, CeremonyID: body.CeremonyID, Response: body.Response, KEK: body.KEK,
	}, &resp) {
		return
	}
	vaultName := defaultVault(body.Vault)
	tok, err := s.sessions.issue(vaultName, time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return
	}
	// Secure is intentionally unset: the portal is plain HTTP on loopback (no
	// TLS), so a Secure cookie would never be sent. HttpOnly + SameSite=Strict +
	// loopback-only binding + the Origin CSRF check are the mitigations.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: loopback HTTP portal, no TLS — see comment
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "vault": vaultName, "unlocked": resp.Unlocked, "presence_token": resp.PresenceToken})
}

// GET /api/passkey/list?vault= — enrolled credentials (names only). Works while
// the vault is locked.
func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	var resp ipc.PasskeyListResp
	if !s.run(w, r, ipc.OpPasskeyList, ipc.PasskeyListReq{Vault: r.URL.Query().Get("vault")}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/passkey/remove {vault, credential_id, password} — revoke. The
// daemon requires the master password (proof-of-presence).
func (s *Server) handlePasskeyRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault        string `json:"vault"`
		CredentialID []byte `json:"credential_id"`
		Password     string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var resp ipc.PasskeyRemoveResp
	if !s.run(w, r, ipc.OpPasskeyRemove, ipc.PasskeyRemoveReq{
		Vault: body.Vault, CredentialID: body.CredentialID, Password: []byte(body.Password),
	}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/passkey/session — reports whether the request carries a valid
// passkey session cookie.
func (s *Server) handlePasskeySession(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	vaultName, ok := s.sessions.lookup(ck.Value, time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": ok, "vault": vaultName})
}
