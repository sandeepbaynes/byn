// Package ui is the daemon-embedded browser admin portal. It serves a
// small single-page app over plain HTTP on loopback (default
// localhost:2967) and translates browser requests into in-process IPC
// dispatch calls, so the portal reuses every business rule the CLI and
// TUI use.
//
// There is no portal login: like `byn ls`, the scope tree and entry NAMES
// are always visible. Reading or editing VALUES requires the target vault
// to be unlocked (a daemon-level state toggled per-vault from the portal);
// a locked vault returns CodeLocked. The portal is loopback-only and takes
// no dependency on any cloud identity. Its CSRF defense is an Origin check
// (see sameOrigin): a browser always sends Origin on a cross-site POST, so
// a malicious page cannot drive the portal even without a session.
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
}

// Server is the embedded portal HTTP server.
type Server struct {
	disp    Dispatcher
	mux     *http.ServeMux
	mu      sync.Mutex // guards httpSrv: Serve sets it, Close (via reload) reads it
	httpSrv *http.Server
	ln      net.Listener
	port    int

	sessions *pkSessions
}

// New constructs a portal server bound to disp. It does not listen until
// Serve is called.
func New(disp Dispatcher, cfg Config) *Server {
	port := cfg.Port
	if port <= 0 {
		port = 2967
	}
	s := &Server{
		disp:     disp,
		mux:      http.NewServeMux(),
		port:     port,
		sessions: newPKSessions(),
	}
	s.routes()
	return s
}

// routes registers every handler. All API endpoints are reachable without
// a login; mutating endpoints are wrapped in sameOrigin (CSRF defense) and
// the daemon enforces vault-lock state for any value read/write.
func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	sub, _ := fs.Sub(assetsFS, "assets")
	fileSrv := http.FileServer(http.FS(sub))
	s.mux.Handle("/static/", http.StripPrefix("/static/", fileSrv))

	s.mux.HandleFunc("/api/status", s.only(http.MethodGet, s.handleStatus))
	s.mux.HandleFunc("/api/audit", s.only(http.MethodGet, s.handleAudit))
	s.mux.HandleFunc("/api/audit/verify", s.only(http.MethodGet, s.handleAuditVerify))
	s.mux.HandleFunc("/api/trust", s.only(http.MethodGet, s.handleTrust))
	s.mux.HandleFunc("/api/trust/remove", s.sameOrigin(s.only(http.MethodPost, s.handleTrustRemove)))

	// Per-vault lock state (no portal session).
	s.mux.HandleFunc("/api/unlock", s.sameOrigin(s.only(http.MethodPost, s.handleUnlock)))
	s.mux.HandleFunc("/api/lock", s.sameOrigin(s.only(http.MethodPost, s.handleLock)))

	// Portal passkey (WebAuthn) ceremonies. begin/finish forward to the daemon;
	// a verified assertion issues a session cookie.
	s.mux.HandleFunc("/api/passkey/register/begin", s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRegisterBegin)))
	s.mux.HandleFunc("/api/passkey/register/finish", s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRegisterFinish)))
	s.mux.HandleFunc("/api/passkey/auth/begin", s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyAuthBegin)))
	s.mux.HandleFunc("/api/passkey/auth/finish", s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyAuthFinish)))
	s.mux.HandleFunc("/api/passkey/list", s.only(http.MethodGet, s.handlePasskeyList))
	s.mux.HandleFunc("/api/passkey/remove", s.sameOrigin(s.only(http.MethodPost, s.handlePasskeyRemove)))
	s.mux.HandleFunc("/api/passkey/session", s.only(http.MethodGet, s.handlePasskeySession))

	// Scope CRUD.
	s.mux.HandleFunc("/api/vaults", s.sameOrigin(s.handleVaults)) // POST create
	s.mux.HandleFunc("/api/vault/delete", s.sameOrigin(s.only(http.MethodPost, s.handleVaultDelete)))
	s.mux.HandleFunc("/api/vault/passwd", s.sameOrigin(s.only(http.MethodPost, s.handleVaultPasswd)))
	s.mux.HandleFunc("/api/projects", s.sameOrigin(s.handleProjects)) // GET list, POST create
	s.mux.HandleFunc("/api/envs", s.sameOrigin(s.handleEnvs))         // GET list, POST create
	s.mux.HandleFunc("/api/project/delete", s.sameOrigin(s.only(http.MethodPost, s.handleProjectDelete)))
	s.mux.HandleFunc("/api/env/delete", s.sameOrigin(s.only(http.MethodPost, s.handleEnvDelete)))
	s.mux.HandleFunc("/api/project/rename", s.sameOrigin(s.only(http.MethodPost, s.handleProjectRename)))
	s.mux.HandleFunc("/api/env/rename", s.sameOrigin(s.only(http.MethodPost, s.handleEnvRename)))
	s.mux.HandleFunc("/api/vault/rename", s.sameOrigin(s.only(http.MethodPost, s.handleVaultRename)))

	// Entry data plane. Reads of names are open; reveal/edit hit the
	// daemon, which returns CodeLocked (423) for a locked vault.
	s.mux.HandleFunc("/api/entries", s.sameOrigin(s.handleEntries)) // GET list, POST put
	s.mux.HandleFunc("/api/entry/reveal", s.sameOrigin(s.only(http.MethodPost, s.handleReveal)))
	s.mux.HandleFunc("/api/entry/delete", s.sameOrigin(s.only(http.MethodPost, s.handleDelete)))
	s.mux.HandleFunc("/api/entry/rename", s.sameOrigin(s.only(http.MethodPost, s.handleRename)))
	s.mux.HandleFunc("/api/byn/write", s.sameOrigin(s.only(http.MethodPost, s.handleBynWrite)))
	s.mux.HandleFunc("/api/fs/listdir", s.sameOrigin(s.only(http.MethodGet, s.handleFSListDir)))
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

// sameOrigin is the portal's CSRF defense. On a mutating (non-GET) request
// it rejects any Origin header that is present and not the portal's own
// loopback origin — a browser always sends Origin on a cross-site POST, so
// a malicious page cannot drive the portal even though there is no session.
// A request with no Origin (a non-browser local client) is allowed: such a
// client could use the daemon's Unix socket directly anyway (SPEC §12.4).
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
