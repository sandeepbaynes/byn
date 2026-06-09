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
	OpTrustList   Op = "trust.list"
	OpTrustRemove Op = "trust.remove"
	OpTrustGrant  Op = "trust.grant"
	OpTrustVerify Op = "trust.verify" // MAC-hardened TOFU check (fp + vk layers)

	// Portal passkey (WebAuthn) ceremonies, per-vault. begin returns options
	// for navigator.credentials.{create,get}; finish verifies the browser's
	// response. Enrollment requires the vault unlocked; revoke is password-gated.
	OpPasskeyRegisterBegin  Op = "passkey.register.begin"
	OpPasskeyRegisterFinish Op = "passkey.register.finish"
	OpPasskeyAuthBegin      Op = "passkey.auth.begin"  //nolint:gosec // G101: op name, not a credential
	OpPasskeyAuthFinish     Op = "passkey.auth.finish" //nolint:gosec // G101: op name, not a credential
	OpPasskeyList           Op = "passkey.list"
	OpPasskeyRemove         Op = "passkey.remove"
)

// AllOps is the canonical op list. Used by the daemon dispatcher to
// surface "unknown op" errors with the supported set.
var AllOps = []Op{
	OpStatus,
	OpVaultInit, OpVaultUnlock, OpVaultLock, OpVaultList, OpVaultDelete,
	OpVaultPasswd, OpVaultRename,
	OpProjectCreate, OpProjectList, OpProjectDelete, OpProjectRename,
	OpEnvCreate, OpEnvList, OpEnvDelete, OpEnvRename,
	OpPut, OpGet, OpList, OpDelete, OpRename,
	OpAuditTail, OpAuditVerify, OpDoctor,
	OpTrustList, OpTrustRemove, OpTrustGrant, OpTrustVerify,
	OpPasskeyRegisterBegin, OpPasskeyRegisterFinish,
	OpPasskeyAuthBegin, OpPasskeyAuthFinish,
	OpPasskeyList, OpPasskeyRemove,
}

// Envelope is the top-level wire frame. Exactly one of Req/Resp/Err
// is non-nil on any given wire frame; the dispatcher chooses based on
// direction.
//
// We use json.RawMessage for Req/Resp so the body can be unmarshaled
// into an op-specific struct after the envelope is parsed.
type Envelope struct {
	V    uint    `json:"v"`
	ID   string  `json:"id"`
	Op   Op      `json:"op,omitempty"`
	Req  []byte  `json:"req,omitempty"`
	Resp []byte  `json:"resp,omitempty"`
	Err  *ErrMsg `json:"err,omitempty"`
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
}

// VaultSummary is the per-vault entry in StatusResp.Vaults. LastActive
// is only populated for unlocked vaults (locked-vault timing is not
// exposed — security finding from the design review).
type VaultSummary struct {
	Name        string     `json:"name"`
	Initialized bool       `json:"initialized"`
	Locked      bool       `json:"locked"`
	LastActive  *time.Time `json:"last_active,omitempty"`
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

// VaultUnlockResp is empty.
type VaultUnlockResp struct{}

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
// the vault is already unlocked.
type VaultDeleteReq struct {
	Name     string `json:"name"`
	Password []byte `json:"password,omitempty"`
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
// unlock); empty when the vault is already unlocked. Refuses the default
// vault and an existing destination name.
type VaultRenameReq struct {
	OldName  string `json:"old_name"`
	NewName  string `json:"new_name"`
	Password []byte `json:"password,omitempty"`
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
type ProjectDeleteReq struct {
	Vault    string `json:"vault,omitempty"`
	Name     string `json:"name"`
	Password []byte `json:"password,omitempty"`
}

// ProjectDeleteResp is empty.
type ProjectDeleteResp struct{}

// ProjectRenameReq renames a project. Password authorizes the rename when
// the vault is locked (one-shot verify, no unlock); empty when unlocked.
type ProjectRenameReq struct {
	Vault    string `json:"vault,omitempty"`
	OldName  string `json:"old_name"`
	NewName  string `json:"new_name"`
	Password []byte `json:"password,omitempty"`
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
// unlocked.
type EnvDeleteReq struct {
	Vault    string `json:"vault,omitempty"`
	Project  string `json:"project"`
	Name     string `json:"name"`
	Password []byte `json:"password,omitempty"`
}

// EnvDeleteResp is empty.
type EnvDeleteResp struct{}

// EnvRenameReq renames a non-default env. Password authorizes the rename
// when the vault is locked (one-shot verify, no unlock); empty when unlocked.
type EnvRenameReq struct {
	Vault    string `json:"vault,omitempty"`
	Project  string `json:"project"`
	OldName  string `json:"old_name"`
	NewName  string `json:"new_name"`
	Password []byte `json:"password,omitempty"`
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
}

// PutResp is empty.
type PutResp struct{}

// GetReq retrieves an env-var entry from Scope. Applies inheritance
// (falls back to env=default when not found in Scope.Env).
type GetReq struct {
	Scope Scope  `json:"scope,omitempty"`
	Name  string `json:"name"`
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
}

// DeleteReq removes an env-var entry. No inheritance — the row must
// exist in Scope.Env. Password authorizes the delete when the vault is
// locked (one-shot verify, no unlock); empty when unlocked.
type DeleteReq struct {
	Scope    Scope  `json:"scope,omitempty"`
	Name     string `json:"name"`
	Password []byte `json:"password,omitempty"`
}

// DeleteResp is empty.
type DeleteResp struct{}

// RenameReq renames an env-var entry in Scope. The entry is
// re-encrypted under the new name's AAD.
type RenameReq struct {
	Scope   Scope  `json:"scope,omitempty"`
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
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
// "default"). The password is ALWAYS required, even when the vault is already
// unlocked: granting trust is a proof-of-presence action, not an ambient one.
// The daemon canonicalizes Path, reads + hashes the file itself, verifies the
// password, then records {canonical path, hash}.
type TrustGrantReq struct {
	Path     string `json:"path"`
	Vault    string `json:"vault,omitempty"`
	Password []byte `json:"password"`
}

// TrustGrantResp reports the result. Changed=true means the path was already
// trusted with a DIFFERENT hash (a re-approval of a modified file), so the
// caller can surface a louder confirmation. SHA256 is the recorded fingerprint.
type TrustGrantResp struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Changed bool   `json:"changed"`
}

// TrustVerifyReq asks the daemon to verify a `.byn` against the hardened trust
// store: it canonicalizes Path, reads + hashes the file, and checks the
// record's MACs. Vault is the file's target vault (keys the vault-key MAC), or
// "default".
type TrustVerifyReq struct {
	Path  string `json:"path"`
	Vault string `json:"vault,omitempty"`
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
