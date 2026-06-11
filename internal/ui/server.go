// Package ui is the daemon-embedded browser admin portal. It serves a
// small single-page app over plain HTTP on loopback (default
// localhost:2967) and translates browser requests into in-process IPC
// dispatch calls, so the portal reuses every business rule the CLI and
// TUI use.
//
// # Trust boundary
//
// The portal binds 127.0.0.1 (loopback), which prevents network access but
// does NOT prevent other local user accounts from reaching the port over TCP
// — loopback has no kernel UID gate on macOS or Linux. The Unix socket path
// (daemon.sock, mode 0600) is peer-UID-gated, so other-UID callers cannot use
// it, but that gate does not extend to the HTTP port.
//
// byn addresses this with an owner-token gate on every /api/* route:
//
//   - On daemon start, LoadOrCreateToken writes a 32-byte random hex string to
//     $BYN_DIR/portal.token at mode 0600. Only the owner UID can read it.
//   - Every /api/* request must carry the X-Byn-Portal-Token header equal to
//     that file's value (constant-time compare). Missing or wrong → 401.
//   - `byn web` reads the token from $BYN_DIR (file-system-gated), opens
//     http://localhost:<port>/?auth=<token>, and the SPA stores it in
//     localStorage so it survives page reloads.
//   - Static assets and the SPA fallback (index.html) are NOT gated — the HTML
//     is harmless without a valid token; the API is the security boundary.
//
// # CSRF defense (sameOrigin)
//
// On top of the owner-token gate, mutating routes are wrapped in sameOrigin:
// a browser always sends Origin on a cross-site POST, so a malicious page
// cannot drive the portal even if it somehow obtains the token via XSS.
// The sameOrigin check complements the token gate; both layers are documented
// together because they solve different halves of the problem:
//
//   - Token: stops non-browser local processes running as a different UID.
//   - sameOrigin: stops browser-based CSRF from a different origin.
//
// NOTE: the pre-existing code comment "such a client could use the daemon's
// Unix socket directly anyway" was incorrect — other-UID local clients CANNOT
// use the Unix socket (peer-UID gated, mode 0600), but they CAN reach the
// loopback HTTP port. sameOrigin is not sufficient on its own; the token gate
// is the correct fix for the other-UID loopback exposure.
//
// There is no portal login: like `byn ls`, the scope tree and entry NAMES
// are always visible. Reading or editing VALUES requires the target vault
// to be unlocked (a daemon-level state toggled per-vault from the portal);
// a locked vault returns CodeLocked. The portal is loopback-only and takes
// no dependency on any cloud identity.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"
)

// Config configures the portal server.
type Config struct {
	// Port is the loopback TCP port to bind (default 2967).
	Port int

	// Token is the owner-token value loaded from $BYN_DIR/portal.token.
	// Every /api/* request must supply this value in the X-Byn-Portal-Token
	// header. An empty token disables the gate (test builds may pass "").
	Token string

	// Bootstrap is the consumer used by POST /api/session/bootstrap to
	// exchange a one-time bootstrap token for the persistent portal token.
	// May be nil in tests that do not exercise the bootstrap flow.
	Bootstrap BootstrapConsumer
}

// BootstrapConsumer is the slice of the daemon that the portal session
// bootstrap needs: consume a one-time bootstrap token and return the
// persistent portal token. The daemon satisfies it via the Daemon struct.
type BootstrapConsumer interface {
	// ConsumeBootstrap consumes the one-time bootstrap token t and returns
	// the persistent portal token, or "" if t is invalid/expired/replayed.
	ConsumeBootstrap(t string) string
}

// Server is the embedded portal HTTP server.
type Server struct {
	disp    Dispatcher
	mux     *http.ServeMux
	mu      sync.Mutex // guards httpSrv: Serve sets it, Close (via reload) reads it
	httpSrv *http.Server
	ln      net.Listener
	port    int
	token   string // owner-token; empty ⇒ gate disabled (tests)

	sessions  *pkSessions
	bootstrap BootstrapConsumer // may be nil (tests that don't need bootstrap)
}

// New constructs a portal server bound to disp. It does not listen until
// Serve is called.
func New(disp Dispatcher, cfg Config) *Server {
	port := cfg.Port
	if port <= 0 {
		port = 2967
	}
	s := &Server{
		disp:      disp,
		mux:       http.NewServeMux(),
		port:      port,
		token:     cfg.Token,
		sessions:  newPKSessions(),
		bootstrap: cfg.Bootstrap,
	}
	s.routes()
	return s
}

// routes registers every handler. Static assets and the SPA fallback are
// ungated (the HTML is harmless without a token). All /api/* routes are gated
// by requireToken (the owner-token check). Mutating /api/* routes are also
// wrapped in sameOrigin (CSRF defense). Both layers are necessary:
//
//   - requireToken: stops other-UID local processes that can reach loopback TCP
//     but cannot read $BYN_DIR/portal.token (mode 0600, owned by daemon UID).
//   - sameOrigin: stops browser CSRF — a browser always sends Origin on a
//     cross-site POST, so a malicious page cannot drive the portal even if it
//     somehow obtained the token via XSS.
func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/favicon.svg", s.handleFavicon)
	sub, _ := fs.Sub(assetsFS, "assets")
	fileSrv := http.FileServer(http.FS(sub))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fileSrv))

	// POST /api/session/bootstrap: one-time bootstrap token exchange (UNGATED —
	// callers don't have the persistent token yet; the bootstrap token IS the
	// credential). CSRF-gated via sameOrigin (browser always sends Origin on
	// cross-origin POSTs, so a malicious page cannot replay a ps-captured token).
	s.mux.HandleFunc("/api/session/bootstrap", s.sameOrigin(s.only(http.MethodPost, s.handleSessionBootstrap)))

	s.mux.HandleFunc("/api/status", s.requireToken(s.only(http.MethodGet, s.handleStatus)))
	s.mux.HandleFunc("/api/audit", s.requireToken(s.only(http.MethodGet, s.handleAudit)))
	s.mux.HandleFunc("/api/audit/verify", s.requireToken(s.only(http.MethodGet, s.handleAuditVerify)))
	s.mux.HandleFunc("/api/trust", s.requireToken(s.only(http.MethodGet, s.handleTrust)))
	s.mux.HandleFunc("/api/trust/remove", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleTrustRemove))))

	// Per-vault lock state (no portal session).
	s.mux.HandleFunc("/api/unlock", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleUnlock))))
	s.mux.HandleFunc("/api/lock", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleLock))))

	// Portal passkey (WebAuthn) ceremonies. begin/finish forward to the daemon;
	// a verified assertion issues a session cookie. The SPA has the token by
	// the time these routes are called, so they carry the same owner-token gate.
	s.mux.HandleFunc("/api/passkey/register/begin", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRegisterBegin))))
	s.mux.HandleFunc("/api/passkey/register/finish", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRegisterFinish))))
	s.mux.HandleFunc("/api/passkey/auth/begin", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyAuthBegin))))
	s.mux.HandleFunc("/api/passkey/auth/finish", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyAuthFinish))))
	s.mux.HandleFunc("/api/passkey/list", s.requireToken(s.only(http.MethodGet, s.handlePasskeyList)))
	s.mux.HandleFunc("/api/passkey/remove", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRemove))))
	s.mux.HandleFunc("/api/passkey/session", s.requireToken(s.only(http.MethodGet, s.handlePasskeySession)))

	// Scope CRUD.
	s.mux.HandleFunc("/api/vaults", s.requireToken(s.sameOrigin(s.handleVaults))) // POST create
	s.mux.HandleFunc("/api/vault/delete", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleVaultDelete))))
	s.mux.HandleFunc("/api/vault/passwd", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleVaultPasswd))))
	s.mux.HandleFunc("/api/projects", s.requireToken(s.sameOrigin(s.handleProjects))) // GET list, POST create
	s.mux.HandleFunc("/api/envs", s.requireToken(s.sameOrigin(s.handleEnvs)))         // GET list, POST create
	s.mux.HandleFunc("/api/project/delete", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleProjectDelete))))
	s.mux.HandleFunc("/api/env/delete", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleEnvDelete))))
	s.mux.HandleFunc("/api/project/rename", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleProjectRename))))
	s.mux.HandleFunc("/api/env/rename", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleEnvRename))))
	s.mux.HandleFunc("/api/vault/rename", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleVaultRename))))

	// Entry data plane. Reads of names are open; reveal/edit hit the
	// daemon, which returns CodeLocked (423) for a locked vault.
	s.mux.HandleFunc("/api/entries", s.requireToken(s.sameOrigin(s.handleEntries))) // GET list, POST put
	s.mux.HandleFunc("/api/entry/reveal", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleReveal))))
	s.mux.HandleFunc("/api/entry/delete", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleDelete))))
	s.mux.HandleFunc("/api/entry/rename", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleRename))))
	// Global config — GET reads (no path, no traversal), POST writes (credential-gated).
	s.mux.HandleFunc("/api/config", s.requireToken(s.handleConfigRoute))
	// config.validate: POST {content} → {errors, parsed?}. sameOrigin — no
	// secrets, but we apply the same cross-origin protection as byn.validate.
	s.mux.HandleFunc("/api/config/validate", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleConfigValidate))))
	s.mux.HandleFunc("/api/byn/write", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleBynWrite))))
	s.mux.HandleFunc("/api/byn/validate", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleBynValidate))))
	s.mux.HandleFunc("/api/byn/simulate", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleBynSimulate))))
	// POST (not GET) with sameOrigin so cross-origin pages cannot use this as
	// an arbitrary file-read oracle even if the daemon's own .byn filter is
	// somehow bypassed. The daemon additionally enforces that the path is a
	// .byn file (filepath.Base == ".byn").
	s.mux.HandleFunc("/api/byn/read", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleBynRead))))
	s.mux.HandleFunc("/api/fs/listdir", s.requireToken(s.sameOrigin(s.only(http.MethodGet, s.handleFSListDir))))
	s.mux.HandleFunc("/api/fs/readfile", s.requireToken(s.sameOrigin(s.only(http.MethodGet, s.handleFSReadFile))))
	// Daemon lifecycle (portal-only, sameOrigin POST).
	s.mux.HandleFunc("/api/daemon/reload", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleDaemonReload))))
	s.mux.HandleFunc("/api/daemon/restart", s.requireToken(s.sameOrigin(s.only(http.MethodPost, s.handleDaemonRestart))))
}

// Listen binds the loopback listener. It binds 127.0.0.1 explicitly —
// never 0.0.0.0 — so the portal is unreachable from the network. A port
// of 0 binds an ephemeral port; Port() then reports the chosen one.
func (s *Server) Listen() error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ui: listen %s: %w", addr, err)
	}
	s.ln = ln
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcp.Port
	}
	return nil
}

// Serve serves HTTP on the bound listener until Close. Listen must be
// called first.
func (s *Server) Serve() error {
	if s.ln == nil {
		return fmt.Errorf("ui: Serve called before Listen")
	}
	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// Publish under the lock so a concurrent Close (from reloadUI) reads a
	// fully-constructed server, then serve WITHOUT the lock held (Serve blocks
	// until Close, so holding it would deadlock the reload).
	s.mu.Lock()
	s.httpSrv = srv
	s.mu.Unlock()
	return srv.Serve(s.ln)
}

// Port returns the bound port.
func (s *Server) Port() int { return s.port }

// Token returns the persistent portal owner-token. Called by the daemon's
// ConsumeBootstrap implementation to hand the SPA the real long-lived token
// after a successful one-time bootstrap exchange.
func (s *Server) Token() string { return s.token }

// Close stops the server.
func (s *Server) Close() error {
	s.mu.Lock()
	srv := s.httpSrv
	s.mu.Unlock()
	if srv != nil {
		return srv.Close()
	}
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// ---- middleware ---------------------------------------------------------

type handlerFunc = http.HandlerFunc

// only restricts a handler to a single HTTP method.
func (s *Server) only(method string, h handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h(w, r)
	}
}

// requireToken is the portal's owner-token gate. Every /api/* request must
// carry an X-Byn-Portal-Token header whose value matches the token loaded from
// $BYN_DIR/portal.token (mode 0600). Reading the file proves same-UID — another
// local user account can reach the loopback TCP port but cannot read the file.
//
// When s.token is empty (tests that do not configure a token), the gate is
// disabled so tests do not need to thread a token through every call.
func (s *Server) requireToken(h handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			got := r.Header.Get("X-Byn-Portal-Token")
			if !tokenMatches(s.token, got) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "portal_token_required"})
				return
			}
		}
		h(w, r)
	}
}

// sameOrigin is the portal's CSRF defense. On a mutating (non-GET) request
// it rejects any Origin header that is present and not the portal's own
// loopback origin — a browser always sends Origin on a cross-site POST, so
// a malicious page cannot drive the portal even without a session.
//
// NOTE: sameOrigin alone is NOT sufficient to gate non-browser local clients.
// A process running as a different UID can reach the loopback HTTP port without
// sending an Origin header, bypassing this check. The requireToken middleware
// provides the UID gate for that threat; sameOrigin covers the browser-CSRF
// threat. Both layers are applied to every /api/* route.
func (s *Server) sameOrigin(h handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(o) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) originAllowed(origin string) bool {
	return origin == fmt.Sprintf("http://localhost:%d", s.port) ||
		origin == fmt.Sprintf("http://127.0.0.1:%d", s.port)
}

// ---- JSON helpers -------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON reads a small JSON body into v, rejecting unknown fields and
// capping the body at 1 MiB.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
