package ipc

import (
	"encoding/json"
	"time"
)

// ProtocolVersion is the current wire-protocol major version. The
// daemon refuses requests whose `v` field is unknown. v2 introduced
// the vault → project → env hierarchy and the Scope substruct on
// data-plane ops.
const ProtocolVersion uint = 2

// ProtocolMin is the oldest protocol version this build accepts on
// the wire. New CLI against an old daemon (or vice versa) checks this
// via OpStatus before any data-plane call. v2 dropped v1 entirely
// (pre-1.0 backward-compat waiver).
const ProtocolMin uint = 2

// Op identifies an operation on the daemon. Dotted names are used
// for grouped subsystems (vault.*, project.*, env.*); flat names are
// kept for the data-plane CRUD that users invoke most often.
type Op string

// Operation registry. Keep names short — they appear in every wire
// frame.
const (
	// Daemon / negotiation
	OpStatus Op = "status"

	// Vault lifecycle (per-vault; replaces the v1 init/unlock/lock
	// which implicitly targeted the only vault).
	OpVaultInit   Op = "vault.init"
	OpVaultUnlock Op = "vault.unlock"
	OpVaultLock   Op = "vault.lock"
	OpVaultList   Op = "vault.list"
	OpVaultDelete Op = "vault.delete"
	OpVaultPasswd Op = "vault.passwd"
	OpVaultRename Op = "vault.rename"

	// Project CRUD
	OpProjectCreate Op = "project.create"
	OpProjectList   Op = "project.list"
	OpProjectDelete Op = "project.delete"
	OpProjectRename Op = "project.rename"

	// Env CRUD (within a project)
	OpEnvCreate Op = "env.create"
	OpEnvList   Op = "env.list"
	OpEnvDelete Op = "env.delete"
	OpEnvClear  Op = "env.clear" // delete all env-vars in an env, keep the env
	OpEnvRename Op = "env.rename"

	// Env-var data-plane (scoped). Flat names because they're the
	// most common user-invoked ops.
	OpPut    Op = "put"
	OpGet    Op = "get"
	OpList   Op = "list"
	OpDelete Op = "delete"
	OpRename Op = "rename"

	// Audit log (per-vault; reads the HMAC-chained log written by
	// dispatch.auditEmit).
	OpAuditTail   Op = "audit.tail"
	OpAuditVerify Op = "audit.verify"

	// Diagnostics. OpDoctor returns a structured health report; the
	// CLI renders it human-readable or as JSON.
	OpDoctor Op = "doctor"

	// Trust store (global, not per-vault): the TOFU list of approved
	// `.byn` files. The portal lists and can revoke entries; granting is
	// gated by the master password (proof-of-presence).
	OpTrustList      Op = "trust.list"
	OpTrustRemove    Op = "trust.remove"
	OpTrustGrant     Op = "trust.grant"
	OpTrustGrantBulk Op = "trust.grant.bulk" // trust many .byn at once (one vault, one password)
	OpTrustVerify    Op = "trust.verify"     // MAC-hardened TOFU check (fp + vk layers)
	OpTrustDiff      Op = "trust.diff"       // diff current file vs the trusted snapshot
	OpBynWrite       Op = "byn.write"        // portal writes a .byn scope file (+ optional trust)
	OpBynValidate    Op = "byn.validate"     // validate .byn content without trusting it
	OpBynSimulate    Op = "byn.simulate"     // simulate exec verdict for a command against .byn content
	OpBynRead        Op = "byn.read"         // read a .byn file with its current trust status
	OpConfigGet      Op = "config.get"       // read raw config file bytes
	OpConfigSet      Op = "config.set"       // write + reload config (credential-gated)
	OpConfigValidate Op = "config.validate"  // validate config content without writing
	OpFSListDir      Op = "fs.listdir"       // list subdirectories for the portal directory picker

	OpExecFetch Op = "exec.fetch"
	OpExecSpawn Op = "exec.spawn" // run a byn exec child SERVER-side under privsep (NU-5; superseded by authorize+redeem)

	// Terminal-anchored exec (Option A, 2026-06-17). The daemon authorizes the
	// exec and mints a one-time token; the privsep helper — spawned by the CLI in
	// the invoking shell's process tree so the child inherits the shell's TCC
	// grant — redeems it for the curated argv+env+profile. Secrets never reach the
	// owner-UID CLI. See specs/2026-06-17-terminal-anchored-exec-design.md.
	OpExecAuthorize Op = "exec.authorize" //nolint:gosec // G101: op name, not a credential
	OpExecRedeem    Op = "exec.redeem"    //nolint:gosec // G101: op name, not a credential

	// Daemon lifecycle (portal-facing). Reload applies a live config reload and
	// returns what changed; Restart performs a graceful shutdown so the OS
	// auto-start (launchd/systemd) or the user can relaunch it.
	OpDaemonReload  Op = "daemon.reload"
	OpDaemonRestart Op = "daemon.restart"

	// Portal passkey (WebAuthn) ceremonies, per-vault. begin returns options
	// for navigator.credentials.{create,get}; finish verifies the browser's
	// response. Enrollment requires the vault unlocked; revoke is password-gated.
	OpPasskeyRegisterBegin  Op = "passkey.register.begin"
	OpPasskeyRegisterFinish Op = "passkey.register.finish"
	OpPasskeyAuthBegin      Op = "passkey.auth.begin"  //nolint:gosec // G101: op name, not a credential
	OpPasskeyAuthFinish     Op = "passkey.auth.finish" //nolint:gosec // G101: op name, not a credential
	OpPasskeyList           Op = "passkey.list"
	OpPasskeyRemove         Op = "passkey.remove"

	// OpWebBootstrap mints a single-use, short-lived (60s) bootstrap token
	// for the portal. Only the socket owner can call this op (UID-gated by
	// the Unix socket). The CLI (`byn web`) calls it and opens
	// ?auth=<bootstrap-token>; the SPA exchanges it at POST
	// /api/session/bootstrap for the persistent portal token and stores that
	// in localStorage. The bootstrap token never reappears after the exchange.
	OpWebBootstrap Op = "web.bootstrap" //nolint:gosec // G101: op name, not a credential

	// OpConfigAuth mints a single-use, short-lived (60s) token that authorizes
	// exactly ONE config WRITE from the portal. Only the socket owner can call it
	// (UID-gated). `byn config-auth` calls it AFTER proving sudo via `sudo -v`
	// (PAM); the owner pastes the returned code into the settings panel, which
	// sends it with the one config write. The daemon consumes it once.
	OpConfigAuth Op = "config.auth" //nolint:gosec // G101: op name, not a credential

	// OpSessionEnd revokes the session token carried in the request Envelope.Session.
	// The request body is empty; the daemon invalidates the token and returns an
	// empty response.  Idempotent (no-op when the token is absent or already expired).
	// The CLI calls this on explicit `byn lock` (Task 3) to guarantee the session
	// is cleared on the daemon side even when the local session file is wiped first.
	OpSessionEnd Op = "session.end" //nolint:gosec // G101: op name, not a credential
)

// AllOps is the canonical op list. Used by the daemon dispatcher to
// surface "unknown op" errors with the supported set.
var AllOps = []Op{
	OpStatus,
	OpVaultInit, OpVaultUnlock, OpVaultLock, OpVaultList, OpVaultDelete,
	OpVaultPasswd, OpVaultRename,
	OpProjectCreate, OpProjectList, OpProjectDelete, OpProjectRename,
	OpEnvCreate, OpEnvList, OpEnvDelete, OpEnvClear, OpEnvRename,
	OpPut, OpGet, OpList, OpDelete, OpRename,
	OpAuditTail, OpAuditVerify, OpDoctor,
	OpTrustList, OpTrustRemove, OpTrustGrant, OpTrustGrantBulk, OpTrustVerify, OpTrustDiff, OpBynWrite, OpBynValidate, OpBynSimulate, OpBynRead, OpFSListDir,
	OpConfigGet, OpConfigSet, OpConfigValidate,
	OpExecFetch, OpExecSpawn, OpExecAuthorize, OpExecRedeem,
	OpDaemonReload, OpDaemonRestart,
	OpPasskeyRegisterBegin, OpPasskeyRegisterFinish,
	OpPasskeyAuthBegin, OpPasskeyAuthFinish,
	OpPasskeyList, OpPasskeyRemove,
	OpWebBootstrap,
	OpConfigAuth,
	OpSessionEnd,
}

// Envelope is the top-level wire frame. Exactly one of Req/Resp/Err
// is non-nil on any given wire frame; the dispatcher chooses based on
// direction.
//
// We use json.RawMessage for Req/Resp so the body can be unmarshaled
// into an op-specific struct after the envelope is parsed.
//
// Session carries an opaque session token (32 random bytes, hex-encoded)
// produced by the daemon when a vault.unlock or passkey PRF cold-unlock
// succeeds.  On request frames the client may include its current token; the
// daemon uses it (NU-3 Task 2+) to skip per-action re-authorization inside
// an active session.  On response frames the daemon sets it when a new session
// is minted (vault.unlock success, passkey auth finish with Unlocked=true).
// omitempty ensures the field is absent on every frame that does not use it,
// preserving backward-compatibility with v1/v2 clients that do not understand
// sessions.
type Envelope struct {
	V       uint    `json:"v"`
	ID      string  `json:"id"`
	Op      Op      `json:"op,omitempty"`
	Req     []byte  `json:"req,omitempty"`
	Resp    []byte  `json:"resp,omitempty"`
	Err     *ErrMsg `json:"err,omitempty"`
	Session []byte  `json:"session,omitempty"` //nolint:gosec // G101: session token, not a static credential
}

// ErrMsg is a structured error returned by the daemon. The client
// renders Message to the user and prints Recover as the recommended
// next command (e.g. "byn daemon start").
type ErrMsg struct {
	Code    ErrCode `json:"code"`
	Message string  `json:"message"`
	Recover string  `json:"recover,omitempty"`
}

// ErrCode is a stable string identifier for an error class. The CLI
// switches on it to drive exit codes and recovery messaging; humans
// don't see it directly.
type ErrCode string

// Error codes. Keep additions backwards-compatible: existing codes
// must never change meaning.
const (
	CodeUnknownOp      ErrCode = "unknown_op"
	CodeBadRequest     ErrCode = "bad_request"
	CodeUnsupportedVer ErrCode = "unsupported_version"
	CodeBinaryTooOld   ErrCode = "binary_too_old"

	// Vault / unlock state.
	CodeLocked        ErrCode = "locked"
	CodeWrongPassword ErrCode = "wrong_password"
	CodeRateLimited   ErrCode = "rate_limited"
	CodeAlreadyInit   ErrCode = "already_init"
	CodeNotInit       ErrCode = "not_init"
	CodeVaultNotFound ErrCode = "vault_not_found"
	CodeVaultExists   ErrCode = "vault_exists"
	CodeFingerprint   ErrCode = "fingerprint_mismatch"

	// Exec / per-action authorization (NU-1).
	CodeTrustDenied  ErrCode = "trust_denied"  // .byn untrusted/changed/tampered — exec blocked
	CodeAuthRequired ErrCode = "auth_required" // auth gate: supply password/presence token or session

	// Project / env.
	CodeProjectNotFound ErrCode = "project_not_found"
	CodeProjectExists   ErrCode = "project_exists"
	CodeEnvNotFound     ErrCode = "env_not_found"
	CodeEnvExists       ErrCode = "env_exists"
	CodeEnvProtected    ErrCode = "env_protected"

	// Entries.
	CodeNotFound      ErrCode = "not_found"
	CodeAlreadyExists ErrCode = "already_exists"
	CodeBadName       ErrCode = "bad_name"

	// Generic.
	CodeInternal ErrCode = "internal"
)

// Scope identifies a (vault, project, env) tuple on a data-plane op.
// Empty fields are filled in by the daemon with the implicit
// defaults: Vault="default", Project="default", Env="default". This
// keeps the wire compact for the common case while letting clients
// target other scopes explicitly.
type Scope struct {
	Vault   string `json:"vault,omitempty"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
}

// ---- Op bodies -----------------------------------------------------------

// StatusReq is empty.
type StatusReq struct{}

// StatusResp reports the daemon's overall state plus per-vault
// summaries. ProtocolMin/Max let clients version-negotiate before
// the first data-plane call.
type StatusResp struct {
	Version     string         `json:"version"`
	ProtocolMin uint           `json:"protocol_min"`
	ProtocolMax uint           `json:"protocol_max"`
	SocketPath  string         `json:"socket_path,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	Vaults      []VaultSummary `json:"vaults"`

	// UIEnabled / UIPort expose the daemon's resolved web-portal config so the
	// owner-UID CLI (`byn web`) need not read the config file directly — under
	// privsep the config lives in the _byn-owned data dir and is unreadable by the
	// owner. Privsep reports whether privilege separation is engaged so `byn exec`
	// learns it from the daemon (authoritative) rather than a misread of the
	// unreadable config, which would silently downgrade exec to the non-privsep
	// (owner-UID child) path. Single source of truth, per "binary = IPC client only".
	UIEnabled bool `json:"ui_enabled"`
	UIPort    int  `json:"ui_port"`
	Privsep   bool `json:"privsep"`
}

// VaultSummary is the per-vault entry in StatusResp.Vaults. LastActive
// is only populated for unlocked vaults (locked-vault timing is not
// exposed — security finding from the design review).
type VaultSummary struct {
	Name        string     `json:"name"`
	Initialized bool       `json:"initialized"`
	Locked      bool       `json:"locked"`
	LastActive  *time.Time `json:"last_active,omitempty"`
	// NU-3 Task 3: populated by handleStatus when the caller has an active session
	// for this vault (checked via the token in Envelope.Session). omitempty ensures
	// these fields are absent for vaults without an active session, preserving
	// backward-compat with older clients that do not know about sessions.
	SessionActive    bool       `json:"session_active,omitempty"`
	SessionExpiresAt *time.Time `json:"session_expires_at,omitempty"`
}

// ---- Vault lifecycle ---------------------------------------------------

// VaultInitReq creates a new vault. Name defaults to "default" when
// empty.
type VaultInitReq struct {
	Name     string `json:"name,omitempty"`
	Password []byte `json:"password"`
}

// VaultInitResp is empty.
type VaultInitResp struct{}

// VaultUnlockReq unlocks the named vault. Name defaults to "default"
// when empty.
type VaultUnlockReq struct {
	Name     string `json:"name,omitempty"`
	Password []byte `json:"password"`
}

// VaultUnlockResp carries the session token minted on successful unlock
// (NU-3).  The CLI stores this token and includes it in subsequent requests
// via Envelope.Session.  omitempty: absent on old daemons that do not support
// sessions (zero-value []byte is omitted), backward-compatible.
type VaultUnlockResp struct {
	// SessionToken is the newly minted session token (32 random bytes,
	// hex-encoded).  Absent when the daemon has not yet implemented sessions
	// (old daemon, new CLI) — the CLI falls back to password-per-action.
	SessionToken []byte `json:"session_token,omitempty"` //nolint:gosec // G101: not a static credential
}

// VaultLockReq locks the named vault. Name="" or Name="default" locks
// the default vault. Name="*" locks all currently-unlocked vaults.
type VaultLockReq struct {
	Name string `json:"name,omitempty"`
}

// VaultLockResp reports the count of vaults that were locked.
type VaultLockResp struct {
	Locked int `json:"locked"`
}

// VaultListReq is empty.
type VaultListReq struct{}

// VaultListResp returns the names + state of every vault present on
// disk (not just those open in memory).
type VaultListResp struct {
	Vaults []VaultSummary `json:"vaults"`
}

// VaultDeleteReq removes a vault from disk. Refuses if Name is empty
// or doesn't validate. Password authorizes the delete when the vault is
// locked (one-shot verify; the vault is NOT left unlocked) — empty when
// the vault is already unlocked. PresenceToken is the portal's passkey
// alternative to Password (one-time, short-lived).
type VaultDeleteReq struct {
	Name          string `json:"name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// VaultPasswdReq changes a vault's master password by re-wrapping the
// vault key. OldPassword authorizes the change (it must unwrap the key);
// the vault key and its data are unchanged, and the lock state is
// preserved.
type VaultPasswdReq struct {
	Name        string `json:"name,omitempty"`
	OldPassword []byte `json:"old_password"`
	NewPassword []byte `json:"new_password"`
}

// VaultPasswdResp is empty.
type VaultPasswdResp struct{}

// VaultRenameReq renames a vault on disk (and its audit trail). Password
// authorizes the rename when the vault is locked (one-shot verify, no
// unlock); empty when the vault is already unlocked. PresenceToken is
// the portal's passkey alternative to Password (one-time, short-lived).
// Refuses the default vault and an existing destination name.
type VaultRenameReq struct {
	OldName       string `json:"old_name"`
	NewName       string `json:"new_name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// VaultRenameResp is empty.
type VaultRenameResp struct{}

// VaultDeleteResp is empty.
type VaultDeleteResp struct{}

// ---- Project CRUD ------------------------------------------------------

// ProjectCreateReq creates a project (and its implicit default env)
// in the named vault. Vault defaults to "default" when empty.
type ProjectCreateReq struct {
	Vault string `json:"vault,omitempty"`
	Name  string `json:"name"`
}

// ProjectCreateResp is empty.
type ProjectCreateResp struct{}

// ProjectListReq lists projects in the named vault.
type ProjectListReq struct {
	Vault string `json:"vault,omitempty"`
}

// ProjectListResp returns projects in name order.
type ProjectListResp struct {
	Projects []ProjectInfo `json:"projects"`
}

// ProjectInfo is one row of ProjectListResp.
type ProjectInfo struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProjectDeleteReq removes a project (and cascades to its envs +
// entries + entry_versions). Password authorizes the delete when the
// vault is locked (one-shot verify, no unlock); empty when unlocked.
// PresenceToken is the portal's passkey alternative to Password (one-time, short-lived).
type ProjectDeleteReq struct {
	Vault         string `json:"vault,omitempty"`
	Name          string `json:"name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// ProjectDeleteResp is empty.
type ProjectDeleteResp struct{}

// ProjectRenameReq renames a project. Password or PresenceToken authorizes
// the rename when no session exists; empty when a valid session is presented.
type ProjectRenameReq struct {
	Vault         string `json:"vault,omitempty"`
	OldName       string `json:"old_name"`
	NewName       string `json:"new_name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// ProjectRenameResp is empty.
type ProjectRenameResp struct{}

// ---- Env CRUD ----------------------------------------------------------

// EnvCreateReq creates a non-default env in the named project. Vault
// defaults to "default"; Project must be provided.
type EnvCreateReq struct {
	Vault   string `json:"vault,omitempty"`
	Project string `json:"project"`
	Name    string `json:"name"`
}

// EnvCreateResp is empty.
type EnvCreateResp struct{}

// EnvListReq lists envs in the named project. Default env is pinned
// first.
type EnvListReq struct {
	Vault   string `json:"vault,omitempty"`
	Project string `json:"project"`
}

// EnvListResp returns envs in (default-first, then name) order.
type EnvListResp struct {
	Envs []EnvInfo `json:"envs"`
}

// EnvInfo is one row of EnvListResp.
type EnvInfo struct {
	Name      string    `json:"name"`
	IsDefault bool      `json:"is_default"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// EnvDeleteReq removes a non-default env. Password authorizes the delete
// when the vault is locked (one-shot verify, no unlock); empty when
// unlocked. PresenceToken is the portal's passkey alternative to Password (one-time, short-lived).
type EnvDeleteReq struct {
	Vault         string `json:"vault,omitempty"`
	Project       string `json:"project"`
	Name          string `json:"name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// EnvDeleteResp is empty.
type EnvDeleteResp struct{}

// EnvRenameReq renames a non-default env. Password or PresenceToken authorizes
// the rename when no session exists; empty when a valid session is presented.
type EnvRenameReq struct {
	Vault         string `json:"vault,omitempty"`
	Project       string `json:"project"`
	OldName       string `json:"old_name"`
	NewName       string `json:"new_name"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// EnvRenameResp is empty.
type EnvRenameResp struct{}

// ---- Env-var data plane (scoped) ---------------------------------------

// PutReq creates or updates an env-var entry in Scope.
type PutReq struct {
	Scope      Scope  `json:"scope,omitempty"`
	Name       string `json:"name"`
	Value      []byte `json:"value"`
	CreateOnly bool   `json:"create_only,omitempty"`
	// Password authorizes the write when no session is present
	// (one-shot verify, no unlock; empty otherwise). PresenceToken is the
	// portal's passkey-ceremony alternative (one-time, short-lived).
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// PutResp is empty.
type PutResp struct{}

// GetReq retrieves an env-var entry from Scope. Applies inheritance
// (falls back to env=default when not found in Scope.Env).
type GetReq struct {
	Scope Scope  `json:"scope,omitempty"`
	Name  string `json:"name"`
	// Password authorizes the read when no session is present
	// (one-shot verify, no unlock; empty otherwise). PresenceToken is the
	// portal's passkey-ceremony alternative (one-time, short-lived).
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// GetResp returns the decrypted value, metadata, and an inheritance
// flag.
type GetResp struct {
	Name      string    `json:"name"`
	Value     []byte    `json:"value"`
	Source    string    `json:"source"` // "scope" or "default" — set on inheritance fallback
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListReq lists env-var entries in Scope (with inheritance from the
// default env merged in for non-default scopes).
type ListReq struct {
	Scope Scope `json:"scope,omitempty"`
}

// ListResp returns metadata for matching entries.
type ListResp struct {
	Secrets []SecretMeta `json:"secrets"`
}

// SecretMeta is the wire form of an env-var entry's metadata.
type SecretMeta struct {
	Name      string    `json:"name"`
	Source    string    `json:"source"` // "scope" or "default"
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Empty is non-nil and true when the vault is unlocked and the stored
	// value is the empty byte sequence. It is omitted (nil) when the vault
	// is locked or the emptiness could not be determined without decryption.
	// Emptiness is derived from ciphertext length (XChaCha20-Poly1305 AEAD
	// overhead is deterministic: 1 + 24 + 16 = 41 bytes for empty plaintext),
	// so no decryption or audit "get" event fires.
	// Note: the List response (and therefore this field) is always gated by
	// the portal token; individual Get/Update/Delete actions require a session
	// or fresh credentials, but the listing of names + empty-indicator is not
	// separately auth-gated.
	Empty *bool `json:"empty,omitempty"`
}

// DeleteReq removes an env-var entry. No inheritance — the row must
// exist in Scope.Env. Password authorizes the delete when the vault is
// locked (one-shot verify, no unlock); empty when unlocked.
type DeleteReq struct {
	Scope    Scope  `json:"scope,omitempty"`
	Name     string `json:"name"`
	Password []byte `json:"password,omitempty"`
	// PresenceToken is the portal's passkey alternative to Password.
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// DeleteResp is empty.
type DeleteResp struct{}

// EnvClearReq deletes ALL env-vars in Scope's env (the env itself is kept).
// Password authorizes the mutation (proof-of-presence), like delete.
type EnvClearReq struct {
	Scope    Scope  `json:"scope,omitempty"`
	Password []byte `json:"password,omitempty"`
	// PresenceToken is the portal's passkey alternative to Password.
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// EnvClearResp reports how many env-vars were deleted.
type EnvClearResp struct {
	Deleted int `json:"deleted"`
}

// RenameReq renames an env-var entry in Scope. The entry is
// re-encrypted under the new name's AAD.
type RenameReq struct {
	Scope   Scope  `json:"scope,omitempty"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
	// Password authorizes the rename when no session is present
	// (one-shot verify, no unlock; empty otherwise). PresenceToken is the
	// portal's passkey-ceremony alternative (one-time, short-lived).
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// RenameResp is empty.
type RenameResp struct{}

// ---- Audit log ---------------------------------------------------------

// AuditTailReq returns the last N events from a vault's audit log in
// chronological order (oldest first within the returned slice).
// Lines <= 0 returns all events.
type AuditTailReq struct {
	Vault string `json:"vault,omitempty"`
	Lines int    `json:"lines,omitempty"`
}

// AuditEvent mirrors audit.Event on the wire. Re-declared here so the
// CLI doesn't have to import internal/audit.
type AuditEvent struct {
	TS            int64  `json:"ts"`
	VaultID       string `json:"vault_id"`
	VaultName     string `json:"vault_name"`
	Project       string `json:"project,omitempty"`
	Env           string `json:"env,omitempty"`
	Kind          string `json:"kind,omitempty"`
	EntryName     string `json:"entry_name,omitempty"`
	BynPath       string `json:"byn_path,omitempty"`
	Command       string `json:"command,omitempty"`
	Op            string `json:"op"`
	Outcome       string `json:"outcome"`
	CallerUID     uint32 `json:"caller_uid,omitempty"`
	CallerPID     int    `json:"caller_pid,omitempty"`
	CallerComm    string `json:"caller_comm,omitempty"`
	CallerPComm   string `json:"caller_pcomm,omitempty"`
	CallerSurface string `json:"caller_surface,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	HMACChain     string `json:"hmac_chain"`
}

// AuditTailResp returns the recovered events.
type AuditTailResp struct {
	Events []AuditEvent `json:"events"`
}

// AuditVerifyReq re-walks the HMAC chain. Vault defaults to "default".
type AuditVerifyReq struct {
	Vault string `json:"vault,omitempty"`
}

// AuditVerifyResp summarises the verification result. If BadIndex >= 0,
// the chain broke at that index — manual triage required.
type AuditVerifyResp struct {
	Total    int `json:"total"`
	BadIndex int `json:"bad_index"` // -1 when intact
}

// ---- Trust store -------------------------------------------------------

// TrustListReq lists the approved `.byn` files. No fields.
type TrustListReq struct{}

// TrustEntry is one trusted `.byn` file on the wire.
type TrustEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// TrustListResp returns every trusted `.byn` file.
type TrustListResp struct {
	Entries []TrustEntry `json:"entries"`
}

// TrustRemoveReq revokes trust for an exact stored path (from TrustListResp).
type TrustRemoveReq struct {
	Path string `json:"path"`
}

// TrustRemoveResp reports whether a record was removed.
type TrustRemoveResp struct {
	Removed bool `json:"removed"`
}

// TrustGrantReq grants TOFU trust to the `.byn` at Path, gated by the master
// password of Vault (the vault the file targets — its [scope] vault, or
// "default"). Granting trust is a proof-of-presence action, not an ambient
// one: an unlocked session is not sufficient consent. Exactly one of Password
// or PresenceToken must be supplied. Password works whether the vault is
// locked or unlocked; PresenceToken requires the vault to be unlocked (to
// derive the vk-MAC key).
type TrustGrantReq struct {
	Path     string `json:"path"`
	Vault    string `json:"vault,omitempty"`
	Password []byte `json:"password,omitempty"`
	// PresenceToken authorizes trust via a fresh passkey ceremony instead of
	// the master password (see PasskeyAuthFinishResp.PresenceToken). One of
	// Password or PresenceToken is required. The token is consumed (one-time)
	// and the vault must be unlocked for the vk-MAC derivation.
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// TrustGrantResp reports the result. Changed=true means the path was already
// trusted with a DIFFERENT hash (a re-approval of a modified file), so the
// caller can surface a louder confirmation. SHA256 is the recorded fingerprint.
// Actions, Auth, Aliases, EnvWildcard, and ActionsWildcard carry the policy
// parsed from the .byn at grant time (spec §4.5 footgun guard — show at
// approval).
type TrustGrantResp struct {
	Path            string            `json:"path"`
	SHA256          string            `json:"sha256"`
	Changed         bool              `json:"changed"`
	Actions         []string          `json:"actions,omitempty"`
	Auth            map[string]string `json:"auth,omitempty"`
	Aliases         map[string]string `json:"aliases,omitempty"`
	EnvWildcard     bool              `json:"env_wildcard,omitempty"`
	ActionsWildcard bool              `json:"actions_wildcard,omitempty"`
}

// TrustGrantBulkReq trusts every path in Paths against one Vault, verifying
// the password (or presence token) ONCE and reusing the derived key — so
// trusting N files costs one KDF, not N. Exactly one of Password or
// PresenceToken must be supplied. Password works whether the vault is locked
// or unlocked; PresenceToken requires the vault to be unlocked.
type TrustGrantBulkReq struct {
	Paths    []string `json:"paths"`
	Vault    string   `json:"vault,omitempty"`
	Password []byte   `json:"password,omitempty"`
	// PresenceToken authorizes bulk trust via a fresh passkey ceremony instead
	// of the master password (see PasskeyAuthFinishResp.PresenceToken).
	// One-time, vault-bound; vault must be unlocked for vk-MAC derivation.
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// TrustGrantResult is one path's outcome. Error is set on a per-file failure
// (e.g. unreadable); the remaining paths still proceed. Actions, Auth, Aliases,
// EnvWildcard, and ActionsWildcard carry the policy parsed from the .byn at
// grant time (spec §4.5 footgun guard — show at approval).
type TrustGrantResult struct {
	Path            string            `json:"path"`
	SHA256          string            `json:"sha256,omitempty"`
	Changed         bool              `json:"changed,omitempty"`
	Error           string            `json:"error,omitempty"`
	Actions         []string          `json:"actions,omitempty"`
	Auth            map[string]string `json:"auth,omitempty"`
	Aliases         map[string]string `json:"aliases,omitempty"`
	EnvWildcard     bool              `json:"env_wildcard,omitempty"`
	ActionsWildcard bool              `json:"actions_wildcard,omitempty"`
}

// TrustGrantBulkResp reports each path's outcome, in request order.
type TrustGrantBulkResp struct {
	Results []TrustGrantResult `json:"results"`
}

// BynWriteReq writes a .byn scope file into Dir (as Dir/.byn). EnvVars becomes
// the [exec] env allowlist. When Trust is set, the just-written file is trusted
// in the same step (Password authorizes the grant, as with trust.grant).
// When Content is non-empty it is written verbatim instead of being generated
// from Scope/EnvVars; the daemon validates Content (errors refuse, warnings
// are allowed). The trust flow is unchanged.
type BynWriteReq struct {
	Dir     string   `json:"dir"`
	Scope   Scope    `json:"scope,omitempty"`
	EnvVars []string `json:"env_vars,omitempty"`
	// Content, when non-empty, is written verbatim as the .byn file (validated
	// first; validation errors refuse the write). Takes precedence over
	// Scope+EnvVars generation.
	Content  []byte `json:"content,omitempty"`
	Trust    bool   `json:"trust,omitempty"`
	Password []byte `json:"password,omitempty"`
	// PresenceToken authorizes trust via a fresh passkey ceremony instead of the
	// master password (see PasskeyAuthFinishResp.PresenceToken). One of Password
	// or PresenceToken is required when Trust is set.
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// BynWriteResp reports the written path and whether trust was granted. When
// Trusted is set, the policy fields carry what the .byn declared at grant time
// (spec §4.5 footgun guard — show at approval).
type BynWriteResp struct {
	Path            string            `json:"path"`
	Trusted         bool              `json:"trusted"`
	Actions         []string          `json:"actions,omitempty"`
	Auth            map[string]string `json:"auth,omitempty"`
	Aliases         map[string]string `json:"aliases,omitempty"`
	EnvWildcard     bool              `json:"env_wildcard,omitempty"`
	ActionsWildcard bool              `json:"actions_wildcard,omitempty"`
}

// ListDirReq lists the contents of Path (empty ⇒ the user's home dir) for
// the portal directory/file picker. The daemon runs as the user, so it exposes
// only what the user can already read. When IncludeFiles is true, regular files
// are included in the results alongside directories (IsDir distinguishes them).
type ListDirReq struct {
	Path         string `json:"path"`
	IncludeFiles bool   `json:"include_files,omitempty"`
}

// DirEntry is one entry in a directory listing.
type DirEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
}

// ListDirResp returns the resolved absolute Path, its Parent ("" at the
// filesystem root), and the name-sorted subdirectories.
type ListDirResp struct {
	Path    string     `json:"path"`
	Parent  string     `json:"parent,omitempty"`
	Entries []DirEntry `json:"entries"`
}

// TrustDiffReq asks the daemon to compare the current on-disk content of Path
// against the snapshot recorded at trust time. No password required — manifests
// are not secrets, and this is read-only (audit-logged).
type TrustDiffReq struct {
	Path string `json:"path"`
}

// TrustDiffResp returns the diff inputs and a mtime-only flag.
// OldSnapshot is the full .byn content at grant time; NewContent is the
// current on-disk content. When MTimeChangedOnly is true the byte content is
// identical but the file's mtime differs from the recorded mtime (a `touch`
// or an edit-then-revert). Trusted=false means no record exists.
type TrustDiffResp struct {
	Path             string `json:"path"`
	Trusted          bool   `json:"trusted"`
	OldSnapshot      []byte `json:"old_snapshot,omitempty"`
	NewContent       []byte `json:"new_content,omitempty"`
	MTimeChangedOnly bool   `json:"mtime_changed_only,omitempty"`
}

// TrustVerifyReq asks the daemon to verify a `.byn` against the hardened trust
// store: it canonicalizes Path, reads + hashes the file, and checks the
// record's MACs. Vault is the file's target vault (keys the vault-key MAC), or
// "default".
type TrustVerifyReq struct {
	Path  string `json:"path"`
	Vault string `json:"vault,omitempty"`
	// Command is the exec'd command this verification authorizes — recorded in
	// the audit log so a .byn-authorized injection is traceable to its command.
	Command string `json:"command,omitempty"`
}

// TrustVerifyResp reports the status: "trusted", "changed" (content differs),
// "untrusted" (no record), "stale" (record predates MAC hardening — re-trust to
// protect), or "tampered" (a MAC failed — forged or copied from another
// machine). VKChecked is true when the vault-key MAC was verified (target vault
// unlocked); when false only the machine-fingerprint MAC was checked (e.g.
// locked discovery).
type TrustVerifyResp struct {
	Path      string `json:"path"`
	Status    string `json:"status"`
	VKChecked bool   `json:"vk_checked"`
}

// ---- Exec data plane -------------------------------------------------------

// ExecFetchReq asks the daemon to authorize a `byn exec` and return the
// values to inject, enforcing the trusted .byn's [exec] env allowlist
// SERVER-side (the daemon reads + parses the file itself; nothing the
// client sends can widen the list). Path="" = ad-hoc exec with no .byn
// (whole-scope injection, the pre-NU behavior). Scope is the CLI-resolved
// scope; the vk-MAC binds the trust record to its vault, so pointing the
// scope at a different vault fails verification.
//
// Password and PresenceToken are only consulted when Path="" (ad-hoc exec)
// and no session is present, OR when Path!="" and the command is not pinned
// in [exec] actions (NU-2). Trusted-.byn exec with a matched action is
// credential-free — both the .byn AND the matching pinned command authorize.
//
// Alias/Argv semantics (NU-2.1):
//
//	Alias == "" (direct form):  Argv holds the full untruncated child argv.
//	Alias != "" (alias form):   Argv holds only the extra passthrough args;
//	                            the daemon looks up Alias in the trust record,
//	                            expands it to its base command, appends Argv,
//	                            and gates the RESOLVED argv through the normal
//	                            pattern matrix. Path must be non-empty for
//	                            alias exec — aliases are defined in a .byn.
type ExecFetchReq struct {
	Path    string `json:"path,omitempty"`
	Scope   Scope  `json:"scope,omitempty"`
	Command string `json:"command,omitempty"` // child argv label (≤200 chars), for audit only
	// Argv is the exact untruncated child argv for the direct form (Alias==""),
	// or the extra passthrough args for the alias form (Alias!="").
	// An old CLI that does not send Argv gets empty-Argv behavior: treated as
	// unmatched → per-action auth required (fail-closed; acceptable version-skew).
	Argv []string `json:"argv,omitempty"`
	// Alias, when non-empty, names a [aliases] entry in the trusted .byn.
	// Path must also be non-empty (aliases require a trusted .byn).
	// The daemon expands the alias value + Argv into the resolved argv, then
	// gates that through the normal [exec] actions pattern matrix.
	Alias string `json:"alias,omitempty"`
	// Password authorizes ad-hoc exec when no session is present, and
	// trusted-path exec when the command is not pinned in [exec] actions
	// (one-shot verify, no unlock; empty otherwise). PresenceToken is the
	// portal's passkey-ceremony alternative (one-time, short-lived).
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
	// ForceAuth makes the daemon require the master password for EVERY run,
	// overriding the trusted-.byn credential-free path. The CLI sets it for
	// `byn exec --no-privsep`: that mode runs the child as the OWNER (env visible
	// to the owner's `ps -E`), so byn demands explicit presence rather than a
	// blind trusted-file run. (Owner decision 2026-06-17: non-privsep/debug runs
	// are always interactive, so a password per run is acceptable.) Privsep exec
	// leaves this false — the trusted .byn + pinned action is the authorization.
	ForceAuth bool `json:"force_auth,omitempty"`
}

// ExecFetchValue is one env var to inject. Callers must zero Value buffers after use.
type ExecFetchValue struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// ExecFetchResp returns the injection set. Wildcard=true: the [exec] env
// allowlist was "*" (CLI prints the loud warning). NoneDeclared=true: a .byn
// was present but declared no [exec] env (CLI prints the note).
// ActionsWildcard=true: the [exec] actions list was "*" — ALL commands run
// re-auth-free (CLI prints a separate loud warning).
// ResolvedArgv is the daemon-computed argv after alias expansion. Non-empty on
// success for the alias path; also returned for the direct path (req.Argv
// echoed back) so the CLI always has a single authoritative contract. Empty
// for ad-hoc exec (no .byn) — the CLI uses its own argv in that case. The CLI
// passes this verbatim to LookPath + syscall.Exec.
type ExecFetchResp struct {
	Values          []ExecFetchValue `json:"values"`
	Wildcard        bool             `json:"wildcard,omitempty"`
	NoneDeclared    bool             `json:"none_declared,omitempty"`
	ActionsWildcard bool             `json:"actions_wildcard,omitempty"`
	// ResolvedArgv is the canonical argv the daemon authorized. For direct exec
	// this is req.Argv verbatim; for alias exec this is the expanded form
	// (alias base + extra args). The CLI executes exactly this, ignoring the
	// locally-constructed argv — single source of truth.
	ResolvedArgv []string `json:"resolved_argv,omitempty"`
}

// ExecSpawnReq runs a byn exec child SERVER-side under privsep (NU-5). It
// carries the same fields as ExecFetchReq for authorization (via the embedded
// ExecFetchReq), PLUS the caller's base environment and the resolved absolute
// target. The 3 stdio fds travel out-of-band via SCM_RIGHTS (the CLI sends them
// with the request; the daemon's handleConn stashes them in the request context
// — Task 8). The authorization gate is shared with exec.fetch: the daemon
// authorizes ExecFetchReq, builds the child env (BaseEnv + injected values), and
// spawns the resolved AbsTarget under the _byn-exec service user via the helper.
type ExecSpawnReq struct {
	ExecFetchReq          // embed: Path, Scope, Command, Argv, Alias, Password, PresenceToken
	BaseEnv      []string `json:"base_env,omitempty"`   // the CLI's environment (owner terminal env, minus sensitive), KEY=VALUE
	AbsTarget    string   `json:"abs_target,omitempty"` // CLI-resolved ABSOLUTE path of the command (argv[0])
}

// ExecSpawnResp returns the child's exit code. A non-zero code is NOT an IPC
// error — the CLI propagates it as its own exit status.
type ExecSpawnResp struct {
	ExitCode int `json:"exit_code"`
}

// ---- Terminal-anchored exec (Option A) -------------------------------------

// ExecAuthorizeReq authorizes a `byn exec` and asks the daemon to mint a
// one-time token the privsep helper will redeem for the curated child argv+env.
// It carries the same fields as ExecFetchReq for authorization (via the embedded
// ExecFetchReq), PLUS the caller's base environment, the CLI-resolved absolute
// target, and the working directory. Secrets are NEVER returned to the
// owner-UID CLI — only the token is; the root helper redeems the env directly.
type ExecAuthorizeReq struct {
	ExecFetchReq          // embed: Path, Scope, Command, Argv, Alias, Password, PresenceToken
	BaseEnv      []string `json:"base_env,omitempty"`   // the CLI's environment (owner terminal env, minus sensitive), KEY=VALUE
	AbsTarget    string   `json:"abs_target,omitempty"` // CLI-resolved ABSOLUTE path of the command (argv[0])
	Cwd          string   `json:"cwd,omitempty"`        // the CLI's working directory (for audit/binding)
}

// ExecAuthorizeResp returns the one-time redemption Token plus the allowlist
// flags the CLI renders (same semantics as ExecFetchResp's flags). The token is
// a capability the helper exchanges for the env via OpExecRedeem; it carries NO
// secrets itself.
type ExecAuthorizeResp struct {
	Token           []byte `json:"token"` //nolint:gosec // G101: one-time capability, not a static credential
	Wildcard        bool   `json:"wildcard,omitempty"`
	NoneDeclared    bool   `json:"none_declared,omitempty"`
	ActionsWildcard bool   `json:"actions_wildcard,omitempty"`
}

// ExecRedeemReq is sent by the privsep helper (peercred MUST be root or
// _byn-exec — never the owner) to exchange a one-time token for the
// daemon-authorized child argv + complete curated env + sandbox profile.
type ExecRedeemReq struct {
	Token []byte `json:"token"` //nolint:gosec // G101: one-time capability, not a static credential
}

// ExecRedeemResp carries the daemon-authorized spawn argv (argv[0] is the
// validated absolute target), the COMPLETE curated child environment as
// KEY=VALUE strings (base env minus dangerous keys, plus injected secrets), and
// the macOS Seatbelt profile to apply ("" ⇒ run unsandboxed, e.g. on Linux). The
// helper sets the child env to exactly Env and never leaks its own.
type ExecRedeemResp struct {
	Argv           []string `json:"argv"`
	Env            []string `json:"env"`
	SandboxProfile string   `json:"sandbox_profile,omitempty"`
}

// ---- byn.validate ----------------------------------------------------------

// BynIssue is one validation issue (error or warning) returned by byn.validate.
type BynIssue struct {
	// Section is the logical section the issue belongs to: "toml", "auth",
	// "exec", "aliases", or "size".
	Section string `json:"section"`
	Message string `json:"message"`
}

// BynValidateReq asks the daemon to validate .byn content without trusting it.
// No auth required — content is client-supplied and contains no secrets.
type BynValidateReq struct {
	Content []byte `json:"content"`
}

// BynValidateResp returns the validation issues. Errors must be fixed before
// the .byn can be trusted; warnings are advisory.
// Parsed is populated when there are ZERO errors (reuses the BynParsed builder
// from byn.read) so the portal can carry the current parsed state into the
// form/builder without a separate round-trip.
type BynValidateResp struct {
	Errors   []BynIssue `json:"errors,omitempty"`
	Warnings []BynIssue `json:"warnings,omitempty"`
	// Parsed is populated when Errors is empty (zero errors). Nil when any error
	// is present or the content fails to parse.
	Parsed *BynParsed `json:"parsed,omitempty"`
}

// ---- byn.simulate ----------------------------------------------------------

// BynSimulateReq asks the daemon to simulate the exec gate verdict for a given
// command line against supplied .byn content. The content is validated first;
// invalid content returns CodeBadRequest. No trust record or live file is used —
// the verdict is derived from the supplied content alone (same matrix as
// exec.fetch, extracted into a shared helper).
type BynSimulateReq struct {
	Content     []byte `json:"content"`
	CommandLine string `json:"command_line"`
}

// BynSimulateResp reports the simulated verdict.
type BynSimulateResp struct {
	// ResolvedArgv is the argv after alias expansion (or the raw tokenization
	// when no alias matched).
	ResolvedArgv []string `json:"resolved_argv,omitempty"`
	// MatchedKind is "action", "wildcard", or "none". Alias involvement is
	// signaled by a non-empty MatchedAlias field.
	MatchedKind string `json:"matched_kind"`
	// MatchedAction is the pattern string that matched (MatchedKind=="action").
	MatchedAction string `json:"matched_action,omitempty"`
	// MatchedAlias is the alias name that expanded before matching an action
	// pattern (non-empty when argv[0] matched an alias).
	MatchedAlias string `json:"matched_alias,omitempty"`
	// Verdict is "free" or "auth".
	Verdict string `json:"verdict"`
	// Reason explains the verdict.
	Reason string `json:"reason"`
}

// ---- byn.read --------------------------------------------------------------

// BynReadReq asks the daemon to read a .byn file and return its content with
// the current trust status. The readBynFile size cap is enforced.
type BynReadReq struct {
	Path string `json:"path"`
}

// BynParsed carries the structured fields extracted from a successfully-parsed
// .byn, for the portal's builder pre-population. Populated by byn.read when
// the content parses without error; nil (omitted) on parse failure.
type BynParsed struct {
	// Scope mirrors [scope].
	Scope struct {
		Vault   string `json:"vault,omitempty"`
		Project string `json:"project,omitempty"`
		Env     string `json:"env,omitempty"`
	} `json:"scope"`
	// Env is [exec].env as a list (never nil; wildcard represented as ["*"]).
	Env []string `json:"env,omitempty"`
	// EnvWildcard is true when [exec].env contains "*".
	EnvWildcard bool `json:"env_wildcard,omitempty"`
	// Actions is [exec].actions as a list.
	Actions []string `json:"actions,omitempty"`
	// ActionsWildcard is true when [exec].actions contains "*".
	ActionsWildcard bool `json:"actions_wildcard,omitempty"`
	// Writable is [exec].writable as a list — extra tool-state dirs the privsep
	// exec child may read/write, on top of the curated defaults.
	Writable []string `json:"writable,omitempty"`
	// Aliases is the [aliases] table.
	Aliases map[string]string `json:"aliases,omitempty"`
	// Auth is the [auth] table.
	Auth map[string]string `json:"auth,omitempty"`
}

// BynReadResp returns the read result.
type BynReadResp struct {
	// Path is the canonicalized absolute path.
	Path string `json:"path"`
	// Content is the raw file bytes.
	Content []byte `json:"content"`
	// TrustStatus mirrors TrustVerifyResp.Status: "trusted", "changed",
	// "untrusted", "stale", or "tampered".
	TrustStatus string `json:"trust_status"`
	// Parsed holds the structured parse of Content when it parses without
	// error. Nil when Content is empty or unparseable; ParseError holds the
	// error in that case so the UI can fall back to raw mode with a notice.
	Parsed *BynParsed `json:"parsed,omitempty"`
	// ParseError holds the first parse error when Parsed is nil and Content
	// is non-empty.
	ParseError string `json:"parse_error,omitempty"`
}

// ---- config.get / config.set -----------------------------------------------

// ConfigGetReq has no fields — returns the global config.
type ConfigGetReq struct{}

// ConfigParsed carries the structured values extracted from a successfully-parsed
// config file, for the portal's visual settings editor pre-population. Populated
// by config.get; nil (omitted) on parse failure, in which case ParseError is set.
type ConfigParsed struct {
	// UIEnabled mirrors [ui] enabled.
	UIEnabled bool `json:"ui_enabled"`
	// UIPort mirrors [ui] port.
	UIPort int `json:"ui_port"`
	// IdleTimeout mirrors [daemon] idle_timeout as a Go duration string ("15m0s").
	IdleTimeout string `json:"idle_timeout"`
	// RevealHideAfter mirrors [ui] reveal_hide_after as a Go duration string ("15s").
	RevealHideAfter string `json:"reveal_hide_after"`
	// SessionTTL mirrors [security] session_ttl as a Go duration string ("12h0m0s").
	SessionTTL string `json:"session_ttl"`
	// SessionIdle mirrors [security] session_idle as a Go duration string ("0s" = inherit).
	SessionIdle string `json:"session_idle"`
	// Privsep mirrors [security] privsep. Tri-state pointer: null = key absent
	// (off, the default), else the explicit bool.
	Privsep *bool `json:"privsep"`
}

// ConfigGetResp returns the raw config file bytes and the path.
type ConfigGetResp struct {
	// Path is the config file path (even when absent — the portal shows defaults).
	Path string `json:"path"`
	// Content is the raw file bytes; empty when the file is absent (defaults apply).
	Content []byte `json:"content,omitempty"`
	// Parsed holds the structured values from the config when it parses without
	// error. Absent file → parsed from Default(). Nil on parse error; ParseError
	// explains why so the portal can fall back to raw mode with a notice.
	Parsed *ConfigParsed `json:"parsed,omitempty"`
	// ParseError is set when Content is non-empty but failed to parse.
	ParseError string `json:"parse_error,omitempty"`
}

// ConfigSetReq writes new config content and triggers a live reload.
// Credential-gated (master password or presence token) because config can
// enable/disable the portal port — daemon-global impact.
type ConfigSetReq struct {
	Content       []byte `json:"content"`
	Password      []byte `json:"password,omitempty"`
	PresenceToken []byte `json:"presence_token,omitempty"`
}

// ConfigSetResp reports what changed after the reload.
type ConfigSetResp struct {
	// ChangeNotes is the human-readable list of what changed (empty when nothing did).
	ChangeNotes []string `json:"change_notes,omitempty"`
}

// ConfigValidateReq asks the daemon to validate config content without writing it.
// No auth required — content is client-supplied and contains no secrets.
type ConfigValidateReq struct {
	Content []byte `json:"content"`
}

// ConfigValidateResp returns the validation result. On error, Errors contains
// one issue and Parsed is nil; on success Errors is empty and Parsed is populated
// so the portal can carry the validated values into the form without a re-fetch.
type ConfigValidateResp struct {
	// Errors contains at most one issue (the first parse/validate error).
	Errors []BynIssue `json:"errors,omitempty"`
	// Parsed is populated when Errors is empty (zero errors) — the structured
	// values extracted from the content, ready for the portal visual form.
	Parsed *ConfigParsed `json:"parsed,omitempty"`
}

// ---- Portal passkey (WebAuthn) ------------------------------------------

// PasskeyRegisterBeginReq starts enrollment of a new passkey for Vault. The
// vault must be unlocked (enrollment is a proof-of-presence action).
type PasskeyRegisterBeginReq struct {
	Vault string `json:"vault,omitempty"`
}

// PasskeyRegisterBeginResp carries the creation options for
// navigator.credentials.create plus the ceremony id that binds the follow-up
// finish call to the server-held challenge.
type PasskeyRegisterBeginResp struct {
	CeremonyID string          `json:"ceremony_id"`
	Options    json.RawMessage `json:"options"`
}

// PasskeyRegisterFinishReq submits the browser's attestation response.
type PasskeyRegisterFinishReq struct {
	Vault      string          `json:"vault,omitempty"`
	CeremonyID string          `json:"ceremony_id"`
	Response   json.RawMessage `json:"response"`
	Label      string          `json:"label,omitempty"`
	// KEK, when present, is the browser's HKDF(prfOut) key. The daemon wraps a
	// second copy of the vault key with it (PRF cold-unlock enrollment). Absent
	// → session-only passkey (PRF unavailable on this authenticator).
	KEK []byte `json:"kek,omitempty"`
}

// PasskeyRegisterFinishResp reports the stored credential.
type PasskeyRegisterFinishResp struct {
	CredentialID []byte `json:"credential_id"`
	Label        string `json:"label"`
	// Unlock is true when a PRF cold-unlock path was enrolled (KEK provided).
	Unlock bool `json:"unlock"`
}

// PasskeyAuthBeginReq starts an assertion (login) ceremony for Vault.
type PasskeyAuthBeginReq struct {
	Vault string `json:"vault,omitempty"`
}

// PasskeyAuthBeginResp carries the request options for
// navigator.credentials.get plus the ceremony id.
type PasskeyAuthBeginResp struct {
	CeremonyID string          `json:"ceremony_id"`
	Options    json.RawMessage `json:"options"`
}

// PasskeyAuthFinishReq submits the browser's assertion response.
type PasskeyAuthFinishReq struct {
	Vault      string          `json:"vault,omitempty"`
	CeremonyID string          `json:"ceremony_id"`
	Response   json.RawMessage `json:"response"`
	// KEK, when present, unwraps the credential's wrapped vault key and unlocks
	// the vault (PRF cold-unlock). Absent → session auth only.
	KEK []byte `json:"kek,omitempty"`
}

// PasskeyAuthFinishResp reports the matched credential and whether the
// assertion also unlocked the vault (PRF cold-unlock).
type PasskeyAuthFinishResp struct {
	CredentialID []byte `json:"credential_id"`
	Unlocked     bool   `json:"unlocked"`
	// PresenceToken is a one-time proof-of-presence the portal can pass to a
	// follow-up trust grant in place of the master password (empty if the vault
	// is not unlocked). Short-lived and single-use.
	PresenceToken []byte `json:"presence_token,omitempty"`
	// SessionToken is minted when Unlocked=true (PRF cold-unlock succeeded).
	// The portal stores this and includes it in subsequent Envelope.Session
	// frames.  omitempty: absent when the vault was not unlocked by this
	// ceremony (session-only passkey or missing KEK).
	SessionToken []byte `json:"session_token,omitempty"` //nolint:gosec // G101: not a static credential
}

// PasskeyInfo is one enrolled credential, names + timestamps only (no secret).
type PasskeyInfo struct {
	CredentialID []byte `json:"credential_id"`
	Label        string `json:"label"`
	CreatedAt    int64  `json:"created_at"`
	// Unlock is true when this credential can cold-unlock the vault (it has a
	// PRF-wrapped key), vs a session-only passkey.
	Unlock bool `json:"unlock"`
}

// PasskeyListReq lists the credentials enrolled for Vault.
type PasskeyListReq struct {
	Vault string `json:"vault,omitempty"`
}

// PasskeyListResp is the enrolled-credential list.
type PasskeyListResp struct {
	Passkeys []PasskeyInfo `json:"passkeys"`
}

// PasskeyRemoveReq revokes a credential. Password-gated (proof-of-presence),
// like trust grants — an ambient unlocked session is not consent.
type PasskeyRemoveReq struct {
	Vault        string `json:"vault,omitempty"`
	CredentialID []byte `json:"credential_id"`
	Password     []byte `json:"password"`
}

// PasskeyRemoveResp reports whether a credential was removed.
type PasskeyRemoveResp struct {
	Removed bool `json:"removed"`
}

// ---- Daemon lifecycle (portal) -----------------------------------------

// DaemonReloadReq has no fields — reloads the live config from disk.
type DaemonReloadReq struct{}

// DaemonReloadResp returns the human-readable change notes from the reload.
// An empty slice means the config was read but nothing changed.
type DaemonReloadResp struct {
	ChangeNotes []string `json:"change_notes,omitempty"`
}

// DaemonRestartReq has no fields — triggers a graceful shutdown of the daemon.
// The portal receives this acknowledgement before the daemon stops; it should
// then poll /api/status until the daemon comes back (via auto-start or manual
// restart with `byn start`).
type DaemonRestartReq struct{}

// DaemonRestartResp carries a human-readable message. The daemon sends this
// response and then shuts down asynchronously (~200ms later).
type DaemonRestartResp struct {
	// Message explains what happened, e.g. "daemon stopping — restart with `byn start`".
	Message string `json:"message"`
}

// ---- Web bootstrap (one-time portal auth token) -----------------------

// WebBootstrapReq has no fields — the daemon mints a token for the caller.
// Only the Unix-socket owner can issue this request (UID-gated).
type WebBootstrapReq struct{} //nolint:gosec // G101: req type for minting, not a credential

// WebBootstrapResp carries the one-time bootstrap token the CLI passes to
// the browser as ?auth=<token>. The SPA exchanges it at
// POST /api/session/bootstrap for the persistent portal token. The bootstrap
// token is single-use and expires after 60 seconds.
type WebBootstrapResp struct {
	Token string `json:"token"` //nolint:gosec // G101: short-lived bootstrap token
}

// ConfigAuthReq has no fields — the daemon mints a one-time config-write token
// for the caller. Only the Unix-socket owner can issue it (UID-gated); the CLI
// must have proven sudo via `sudo -v` BEFORE calling.
type ConfigAuthReq struct{} //nolint:gosec // G101: req type for minting, not a credential

// ConfigAuthResp carries the single-use code the owner pastes into the settings
// panel to authorize ONE config write. Single-use; expires after 60 seconds.
type ConfigAuthResp struct {
	Token string `json:"token"` //nolint:gosec // G101: short-lived config-write token
}

// ---- Diagnostics -------------------------------------------------------

// DoctorReq runs a battery of self-checks on the daemon and the
// currently-loaded vaults. No request fields today.
type DoctorReq struct{}

// DoctorCheck is one named check + its result. Severity is "ok" / "warn"
// / "fail"; the CLI exits nonzero if any "fail" appears.
type DoctorCheck struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

// DoctorResp is the full diagnostic report.
type DoctorResp struct {
	Checks []DoctorCheck `json:"checks"`
}

// ---- Session (NU-3) ----------------------------------------------------

// SessionEndReq ends the session carried in the request Envelope.Session.
// No request body fields — the token to revoke is in the envelope header.
type SessionEndReq struct{} //nolint:gosec // G101: req type, not a static credential

// SessionEndResp is empty — the op is idempotent; the caller should not
// branch on whether a token was actually present.
type SessionEndResp struct{} //nolint:gosec // G101: resp type, not a static credential
