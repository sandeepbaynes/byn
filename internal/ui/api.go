package ui

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// maxImportFileSize is the upper bound on file content read by the import
// browse endpoint. Generous but bounded to prevent runaway reads.
const maxImportFileSize = 4 << 20 // 4 MiB

// GET /api/audit?vault=&n= — recent audit events for a vault. Audit metadata
// is not secret, so this works regardless of lock state (mirrors `byn audit`).
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n := 100
	if v := q.Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	var resp ipc.AuditTailResp
	if !s.run(w, r, ipc.OpAuditTail, ipc.AuditTailReq{Vault: q.Get("vault"), Lines: n}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/audit/verify?vault= — re-walk the HMAC chain for a vault.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	var resp ipc.AuditVerifyResp
	if !s.run(w, r, ipc.OpAuditVerify, ipc.AuditVerifyReq{Vault: r.URL.Query().Get("vault")}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/trust — list TOFU-approved `.byn` files (global, no secrets).
func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	var resp ipc.TrustListResp
	if !s.run(w, r, ipc.OpTrustList, ipc.TrustListReq{}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/trust/remove {path} — revoke trust for a `.byn` file.
func (s *Server) handleTrustRemove(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var resp ipc.TrustRemoveResp
	if !s.run(w, r, ipc.OpTrustRemove, ipc.TrustRemoveReq{Path: b.Path}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// scopeBody is the JSON shape browsers send to target a scope.
type scopeBody struct {
	Vault   string `json:"vault"`
	Project string `json:"project"`
	Env     string `json:"env"`
}

func (b scopeBody) toIPC() ipc.Scope {
	return ipc.Scope{Vault: b.Vault, Project: b.Project, Env: b.Env}
}

func scopeFromQuery(r *http.Request) ipc.Scope {
	q := r.URL.Query()
	return ipc.Scope{Vault: q.Get("vault"), Project: q.Get("project"), Env: q.Get("env")}
}

// writeIPCErr translates a daemon error into an HTTP response.
func writeIPCErr(w http.ResponseWriter, e *ipc.ErrMsg) {
	writeJSON(w, httpStatusForCode(e.Code), map[string]string{
		"error":   e.Message,
		"code":    string(e.Code),
		"recover": e.Recover,
	})
}

// dispatch runs op and writes the daemon error to w if any. Returns true
// when the caller should continue (op succeeded).
func (s *Server) run(w http.ResponseWriter, r *http.Request, op ipc.Op, req, resp any) bool {
	ipcErr, err := s.call(r.Context(), op, req, resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if ipcErr != nil {
		writeIPCErr(w, ipcErr)
		return false
	}
	return true
}

// runInVault is like run but attaches the portal's stored session token for
// vaultName (if any) to the in-process envelope.  Any session token returned
// by the daemon is stored back into the portal's per-vault token map so
// subsequent ops in the same vault reuse it without re-prompting.
//
// Use this for every handler that operates on a specific vault and might
// benefit from the session the portal holds (reveal, put, delete, rename,
// project/env CRUD on unlocked vaults, etc.).
func (s *Server) runInVault(w http.ResponseWriter, r *http.Request, vaultName string, op ipc.Op, req, resp any) bool {
	ipcErr, err := s.callInVault(r.Context(), vaultName, op, req, resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if ipcErr != nil {
		writeIPCErr(w, ipcErr)
		return false
	}
	return true
}

// GET /api/status — vault list + lock state. Public so the unlock screen
// can populate before authentication. Carries no secret values.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var resp ipc.StatusResp
	if !s.run(w, r, ipc.OpStatus, ipc.StatusReq{}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/unlock {vault, password} — unlock a single vault's key in the
// daemon and capture the minted session token in the portal's in-memory map.
// Subsequent ops routed through runInVault automatically carry this token so
// the user authenticates once per portal session.
//
// Token secrecy: the token is stored only in the Go process heap (sync.Map)
// and never sent to the browser.  The JS does NOT need to track it; the
// portal Go layer threads it transparently via callInVault.
func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault    string `json:"vault"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	vaultName := defaultVault(body.Vault)
	req := ipc.VaultUnlockReq{Name: body.Vault, Password: []byte(body.Password)}
	var unlockResp ipc.VaultUnlockResp
	ipcErr, returned, err := s.callCapture(r.Context(), s.loadVaultSession(vaultName), ipc.OpVaultUnlock, req, &unlockResp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ipcErr != nil {
		writeIPCErr(w, ipcErr)
		return
	}
	// Store the session token minted by the daemon.  The response body carries
	// it in SessionToken; the envelope header has it in resp.Session.  Use
	// whichever is present (body is authoritative; header is the fallback).
	if tok := unlockResp.SessionToken; len(tok) > 0 {
		s.storeVaultSession(vaultName, tok)
	} else if len(returned) > 0 {
		s.storeVaultSession(vaultName, returned)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "vault": body.Vault})
}

// POST /api/lock {vault} — re-lock a single vault (zeroes its key). Empty
// or "*" locks every unlocked vault.  Clears the portal's in-memory session
// token(s) for the affected vault(s) so subsequent ops re-authenticate.
func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Vault string `json:"vault"`
	}
	_ = decodeJSON(r, &body) // body optional
	name := body.Vault
	if name == "" {
		name = "*"
	}
	if !s.run(w, r, ipc.OpVaultLock, ipc.VaultLockReq{Name: name}, &ipc.VaultLockResp{}) {
		return
	}
	// Mirror the lock on the portal's session map: the daemon ended the
	// session(s) on its side when it processed the lock; clear locally too.
	if name == "*" {
		s.clearAllVaultSessions()
	} else {
		s.clearVaultSession(name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/vaults {name, password} — create a vault and unlock it so it
// is immediately usable.  Captures the session token minted on unlock.
func (s *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pw := []byte(body.Password)
	if !s.run(w, r, ipc.OpVaultInit, ipc.VaultInitReq{Name: body.Name, Password: pw}, &ipc.VaultInitResp{}) {
		return
	}
	// Init leaves the vault locked; unlock it so the user can use it now and
	// capture the minted session token.
	vaultName := defaultVault(body.Name)
	var unlockResp ipc.VaultUnlockResp
	ipcErr, returned, err := s.callCapture(r.Context(), nil, ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: body.Name, Password: pw}, &unlockResp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ipcErr != nil {
		writeIPCErr(w, ipcErr)
		return
	}
	if tok := unlockResp.SessionToken; len(tok) > 0 {
		s.storeVaultSession(vaultName, tok)
	} else if len(returned) > 0 {
		s.storeVaultSession(vaultName, returned)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "vault": body.Name})
}

// /api/projects — GET lists projects in a vault; POST creates one.
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var resp ipc.ProjectListResp
		req := ipc.ProjectListReq{Vault: r.URL.Query().Get("vault")}
		if !s.run(w, r, ipc.OpProjectList, req, &resp) {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var b struct{ Vault, Name string }
		if err := decodeJSON(r, &b); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !s.run(w, r, ipc.OpProjectCreate, ipc.ProjectCreateReq{Vault: b.Vault, Name: b.Name}, nil) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// /api/envs — GET lists envs in a project; POST creates one.
func (s *Server) handleEnvs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		var resp ipc.EnvListResp
		req := ipc.EnvListReq{Vault: q.Get("vault"), Project: q.Get("project")}
		if !s.run(w, r, ipc.OpEnvList, req, &resp) {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var b struct{ Vault, Project, Name string }
		if err := decodeJSON(r, &b); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !s.run(w, r, ipc.OpEnvCreate, ipc.EnvCreateReq{Vault: b.Vault, Project: b.Project, Name: b.Name}, nil) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// POST /api/project/delete {vault, name, password?, presence_token?}. Password
// (or presence_token) authorizes the delete when the vault is locked or when
// when no session is present (one-shot verify, no unlock).
func (s *Server) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Vault         string `json:"vault"`
		Name          string `json:"name"`
		Password      string `json:"password"`
		PresenceToken []byte `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.ProjectDeleteReq{Vault: b.Vault, Name: b.Name, Password: []byte(b.Password), PresenceToken: b.PresenceToken}
	if !s.run(w, r, ipc.OpProjectDelete, req, nil) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/env/delete {vault, project, name, password?, presence_token?}.
func (s *Server) handleEnvDelete(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Vault         string `json:"vault"`
		Project       string `json:"project"`
		Name          string `json:"name"`
		Password      string `json:"password"`
		PresenceToken []byte `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.EnvDeleteReq{Vault: b.Vault, Project: b.Project, Name: b.Name, Password: []byte(b.Password), PresenceToken: b.PresenceToken}
	if !s.run(w, r, ipc.OpEnvDelete, req, nil) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/vault/delete {name, password?, presence_token?} — the default
// vault is protected; a locked vault can be deleted by supplying the password
// (or presence_token when no session is present).
func (s *Server) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name          string `json:"name"`
		Password      string `json:"password"`
		PresenceToken []byte `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.VaultDeleteReq{Name: b.Name, Password: []byte(b.Password), PresenceToken: b.PresenceToken}
	if !s.run(w, r, ipc.OpVaultDelete, req, nil) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/vault/passwd {vault, old_password, new_password} — change a
// vault's master password (re-wrap). Data and lock state are unchanged.
func (s *Server) handleVaultPasswd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Vault       string `json:"vault"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.VaultPasswdReq{
		Name:        b.Vault,
		OldPassword: []byte(b.OldPassword),
		NewPassword: []byte(b.NewPassword),
	}
	if !s.run(w, r, ipc.OpVaultPasswd, req, &ipc.VaultPasswdResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// /api/entries — GET lists entries (names + inheritance source, no
// values); POST stores an entry.
func (s *Server) handleEntries(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var resp ipc.ListResp
		if !s.run(w, r, ipc.OpList, ipc.ListReq{Scope: scopeFromQuery(r)}, &resp) {
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var body struct {
			Scope         scopeBody `json:"scope"`
			Name          string    `json:"name"`
			Value         string    `json:"value"`
			CreateOnly    bool      `json:"create_only"`
			Password      string    `json:"password"`
			PresenceToken []byte    `json:"presence_token"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req := ipc.PutReq{Scope: body.Scope.toIPC(), Name: body.Name, Value: []byte(body.Value), CreateOnly: body.CreateOnly, Password: []byte(body.Password), PresenceToken: body.PresenceToken}
		if !s.runInVault(w, r, body.Scope.Vault, ipc.OpPut, req, &ipc.PutResp{}) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// POST /api/entry/reveal {scope, name, password?, presence_token?} — the audited value read.
// When no portal session is active (or [auth] always policy applies) the daemon
// returns auth_required unless the caller supplies a master password or a
// one-time presence_token.  With an active portal session the gate passes without
// re-prompting — the JS apiWithAuth handles the auth_required fallback for the
// "no session / session expired" case.
func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody `json:"scope"`
		Name          string    `json:"name"`
		Password      string    `json:"password"`
		PresenceToken []byte    `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var resp ipc.GetResp
	req := ipc.GetReq{Scope: body.Scope.toIPC(), Name: body.Name, Password: []byte(body.Password), PresenceToken: body.PresenceToken}
	if !s.runInVault(w, r, body.Scope.Vault, ipc.OpGet, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":   resp.Name,
		"value":  string(resp.Value),
		"source": resp.Source,
	})
}

// POST /api/entry/delete {scope, name, password?, presence_token?}. Password
// (or presence_token) authorizes the delete when the vault is locked or when
// when no session is present (one-shot verify, no unlock).
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody `json:"scope"`
		Name          string    `json:"name"`
		Password      string    `json:"password"`
		PresenceToken []byte    `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.DeleteReq{Scope: body.Scope.toIPC(), Name: body.Name, Password: []byte(body.Password), PresenceToken: body.PresenceToken}
	if !s.runInVault(w, r, body.Scope.Vault, ipc.OpDelete, req, &ipc.DeleteResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/entry/rename {scope, old_name, new_name, password?, presence_token?}.
// The daemon requires a master password or presence_token when no session is present.
func (s *Server) handleRename(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope         scopeBody `json:"scope"`
		OldName       string    `json:"old_name"`
		NewName       string    `json:"new_name"`
		Password      string    `json:"password"`
		PresenceToken []byte    `json:"presence_token"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.RenameReq{Scope: body.Scope.toIPC(), OldName: body.OldName, NewName: body.NewName, Password: []byte(body.Password), PresenceToken: body.PresenceToken}
	if !s.runInVault(w, r, body.Scope.Vault, ipc.OpRename, req, &ipc.RenameResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/project/rename {vault, old_name, new_name, password?}.
func (s *Server) handleProjectRename(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Vault    string `json:"vault"`
		OldName  string `json:"old_name"`
		NewName  string `json:"new_name"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.ProjectRenameReq{Vault: b.Vault, OldName: b.OldName, NewName: b.NewName, Password: []byte(b.Password)}
	if !s.runInVault(w, r, b.Vault, ipc.OpProjectRename, req, &ipc.ProjectRenameResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/env/rename {vault, project, old_name, new_name, password?}.
func (s *Server) handleEnvRename(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Vault    string `json:"vault"`
		Project  string `json:"project"`
		OldName  string `json:"old_name"`
		NewName  string `json:"new_name"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.EnvRenameReq{Vault: b.Vault, Project: b.Project, OldName: b.OldName, NewName: b.NewName, Password: []byte(b.Password)}
	if !s.runInVault(w, r, b.Vault, ipc.OpEnvRename, req, &ipc.EnvRenameResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/vault/rename {old_name, new_name, password?, presence_token?} — Password
// (or presence_token) authorizes the rename when the vault is locked or when
// when no session is present (one-shot verify, no unlock). The vault is
// left locked after rename.
func (s *Server) handleVaultRename(w http.ResponseWriter, r *http.Request) {
	var b struct {
		OldName       string `json:"old_name"`
		NewName       string `json:"new_name"`
		Password      string `json:"password"`
		PresenceToken []byte `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.VaultRenameReq{OldName: b.OldName, NewName: b.NewName, Password: []byte(b.Password), PresenceToken: b.PresenceToken}
	if !s.run(w, r, ipc.OpVaultRename, req, &ipc.VaultRenameResp{}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// POST /api/byn/write {dir, content?, scope?, env_vars[], trust, password?} —
// writes a .byn scope file into dir and, when trust is set, trusts it
// (password-gated). When content is provided it is written verbatim and the
// daemon derives the target vault from the parsed [scope].vault; scope/env_vars
// are ignored in that case.
func (s *Server) handleBynWrite(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Dir           string    `json:"dir"`
		Content       string    `json:"content"`
		Scope         scopeBody `json:"scope"`
		EnvVars       []string  `json:"env_vars"`
		Trust         bool      `json:"trust"`
		Password      string    `json:"password"`
		PresenceToken []byte    `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.BynWriteReq{Dir: b.Dir, Scope: b.Scope.toIPC(), EnvVars: b.EnvVars, Trust: b.Trust, PresenceToken: b.PresenceToken}
	if b.Content != "" {
		req.Content = []byte(b.Content)
	}
	if b.Password != "" {
		req.Password = []byte(b.Password)
	}
	var resp ipc.BynWriteResp
	if !s.run(w, r, ipc.OpBynWrite, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/fs/listdir?path=... lists subdirectories for the directory picker.
func (s *Server) handleFSListDir(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := ipc.ListDirReq{
		Path:         q.Get("path"),
		IncludeFiles: q.Get("include_files") == "1" || q.Get("include_files") == "true",
	}
	var resp ipc.ListDirResp
	if !s.run(w, r, ipc.OpFSListDir, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /api/fs/readfile?path=... reads a plain-text file for the import flow.
// The portal server runs as the daemon user, so it can access any file the user
// owns. Capped at maxImportFileSize bytes. sameOrigin + requireToken gated.
// Returns {content: "<text>"}. Does NOT accept directory paths.
func (s *Server) handleFSReadFile(w http.ResponseWriter, r *http.Request) {
	path := filepath.Clean(r.URL.Query().Get("path"))
	if path == "" || path == "." {
		writeErr(w, http.StatusBadRequest, "path required")
		return
	}
	info, err := os.Stat(path) // #nosec G304 -- user-named; portal runs as the user
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if info.IsDir() {
		writeErr(w, http.StatusBadRequest, "path is a directory")
		return
	}
	f, err := os.Open(path) // #nosec G304 -- user-named; portal runs as the user
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() { _ = f.Close() }()
	lr := io.LimitReader(f, maxImportFileSize+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if int64(len(data)) > maxImportFileSize {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large (max 4 MiB)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"content": string(data)})
}

// POST /api/byn/validate {content} — validate .byn content without trusting.
// Returns {errors[{section,message}], warnings[...]}. No auth required.
func (s *Server) handleBynValidate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.BynValidateReq{Content: []byte(b.Content)}
	var resp ipc.BynValidateResp
	if !s.run(w, r, ipc.OpBynValidate, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/byn/simulate {content, command_line} — simulate exec verdict.
// Returns {resolved_argv, matched_kind, matched_action, matched_alias,
// verdict, reason}. No auth required.
func (s *Server) handleBynSimulate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Content     string `json:"content"`
		CommandLine string `json:"command_line"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.BynSimulateReq{Content: []byte(b.Content), CommandLine: b.CommandLine}
	var resp ipc.BynSimulateResp
	if !s.run(w, r, ipc.OpBynSimulate, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleConfigRoute dispatches /api/config: GET reads, POST writes.
// POST is wrapped in sameOrigin so cross-origin pages cannot mutate daemon
// config. GET is open — config contains no secrets (mirrors GET /api/trust).
func (s *Server) handleConfigRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleConfigGet(w, r)
	case http.MethodPost:
		// sameOrigin inline — POST changes daemon settings, so cross-site
		// requests must be rejected.
		if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(o) {
			writeErr(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		s.handleConfigSet(w, r)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// GET /api/config — return the raw global config TOML and its path.
// Config content holds no secrets (it stores settings like port and timeouts),
// so GET is acceptable — same logic as GET /api/trust. There is no client-
// controlled path, so there is no traversal surface.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	var resp ipc.ConfigGetResp
	if !s.run(w, r, ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp) {
		return
	}
	out := map[string]any{
		"path":    resp.Path,
		"content": string(resp.Content),
	}
	// Parsed is forwarded as-is (nil → omitted from JSON); parse_error is
	// forwarded so the portal visual editor can fall back to raw mode with a notice.
	if resp.Parsed != nil {
		out["parsed"] = resp.Parsed
	}
	if resp.ParseError != "" {
		out["parse_error"] = resp.ParseError
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/config {content, password?, presence_token?} — validate + atomic-
// write + reload the global config. Credential-gated unconditionally (the
// daemon always requires a password or passkey presence token because config
// controls the daemon's own security settings).
func (s *Server) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Content       string `json:"content"`
		Password      string `json:"password"`
		PresenceToken []byte `json:"presence_token"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.ConfigSetReq{
		Content:       []byte(b.Content),
		PresenceToken: b.PresenceToken,
	}
	if b.Password != "" {
		req.Password = []byte(b.Password)
	}
	var resp ipc.ConfigSetResp
	if !s.run(w, r, ipc.OpConfigSet, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/config/validate {content} — validate config content without writing.
// Returns {errors?, parsed?}. No auth required; no disk access.
func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.ConfigValidateReq{Content: []byte(b.Content)}
	var resp ipc.ConfigValidateResp
	if !s.run(w, r, ipc.OpConfigValidate, req, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/byn/read {path} — read a .byn file with trust status.
// Returns {path, content (string), trust_status}.
// POST (not GET) with sameOrigin (see routes) so cross-origin pages cannot
// drive this even on browsers that omit Origin for plain GETs. The daemon
// additionally enforces that the path basename is exactly ".byn".
func (s *Server) handleBynRead(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req := ipc.BynReadReq{Path: b.Path}
	var resp ipc.BynReadResp
	if !s.run(w, r, ipc.OpBynRead, req, &resp) {
		return
	}
	// Encode content as string so JS can use it directly.
	// Parsed is forwarded as-is (nil → omitted from JSON); parse_error
	// is forwarded so the portal can fall back to raw mode with a notice.
	out := map[string]any{
		"path":         resp.Path,
		"content":      string(resp.Content),
		"trust_status": resp.TrustStatus,
	}
	if resp.Parsed != nil {
		out["parsed"] = resp.Parsed
	}
	if resp.ParseError != "" {
		out["parse_error"] = resp.ParseError
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/daemon/reload {} — live config reload (no credentials). Returns
// the change_notes so the portal can display what took effect.
func (s *Server) handleDaemonReload(w http.ResponseWriter, r *http.Request) {
	var resp ipc.DaemonReloadResp
	if !s.run(w, r, ipc.OpDaemonReload, ipc.DaemonReloadReq{}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/daemon/restart {} — graceful shutdown. The daemon acknowledges,
// then stops ~200ms later. The browser should poll /api/status until the
// daemon returns (via auto-start or `byn start`).
func (s *Server) handleDaemonRestart(w http.ResponseWriter, r *http.Request) {
	var resp ipc.DaemonRestartResp
	if !s.run(w, r, ipc.OpDaemonRestart, ipc.DaemonRestartReq{}, &resp) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/session/bootstrap {token} — one-time bootstrap token exchange.
//
// This endpoint is UNGATED (no X-Byn-Portal-Token required) because the caller
// does not yet have the persistent portal token; the bootstrap token IS the
// credential. It is CSRF-gated via sameOrigin (see routes): a browser always
// sends Origin on a cross-site POST, so a malicious page cannot replay a
// ps-captured bootstrap token — the short 60s TTL is a secondary defence.
//
// On success the response carries the persistent portal token, which the SPA
// stores in localStorage and uses for all subsequent /api/* calls.
func (s *Server) handleSessionBootstrap(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Token string `json:"token"` //nolint:gosec // G101: incoming bootstrap token, not a credential we store
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.bootstrap == nil {
		writeErr(w, http.StatusServiceUnavailable, "bootstrap not available")
		return
	}
	portalToken := s.bootstrap.ConsumeBootstrap(b.Token)
	if portalToken == "" {
		writeErr(w, http.StatusUnauthorized, "invalid or expired bootstrap token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"portal_token": portalToken})
}
