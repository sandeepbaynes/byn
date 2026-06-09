package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// connReadTimeout caps how long the daemon will wait for a single
// envelope on an accepted connection.
const connReadTimeout = 30 * time.Second

func (d *Daemon) handleConn(conn net.Conn) {
	// Peer-UID enforcement (and capture the peer PID for the audit trail).
	uid, pid, err := peerCred(conn)
	if err == nil && uid != d.ownerUID {
		_ = ipc.WriteFrame(conn, ipc.NewError("", ipc.CodeBadRequest,
			fmt.Sprintf("connection from uid %d rejected (owner uid is %d)", uid, d.ownerUID),
			""))
		return
	}
	if err != nil && !errors.Is(err, ErrNotUnix) {
		_ = ipc.WriteFrame(conn, ipc.NewError("", ipc.CodeInternal,
			fmt.Sprintf("could not verify peer credentials: %v", err), ""))
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))
	env, err := ipc.ReadEnvelope(conn)
	if err != nil {
		id := ""
		if env != nil {
			id = env.ID
		}
		if errors.Is(err, ipc.ErrUnsupportedVersion) {
			_ = ipc.WriteFrame(conn, ipc.NewError(id, ipc.CodeUnsupportedVer,
				err.Error(), "upgrade your byn CLI or daemon"))
			return
		}
		_ = ipc.WriteFrame(conn, ipc.NewError(id, ipc.CodeBadRequest,
			err.Error(), ""))
		return
	}
	// Clear deadline for the rest of this handler; long-running ops
	// (init, unlock) use Argon2 and shouldn't time out at 30s.
	_ = conn.SetReadDeadline(time.Time{})

	// Per-request context derived from the daemon's root context, so
	// in-flight SQLite + audit calls observe Shutdown. Falls back to
	// context.Background() if Start hasn't established a root yet
	// (e.g. during tests that drive dispatch directly).
	root := d.rootCtx
	if root == nil {
		root = context.Background()
	}
	if err == nil {
		root = withCaller(root, socketCaller(uid, pid))
	}
	resp := d.dispatch(root, env)
	_ = ipc.WriteFrame(conn, resp)
}

// Dispatch routes one IPC envelope in-process and returns the response.
// It is the entry point the embedded web UI uses, so browser requests go
// through the exact same handlers (scope resolution, audit, lock checks)
// as Unix-socket clients.
func (d *Daemon) Dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	// Portal requests run in-process; tag them so the audit trail records
	// "portal" (browser) rather than a Unix-socket peer.
	return d.dispatch(withCaller(ctx, d.portalCaller()), env)
}

// dispatch routes one envelope to the right handler.
func (d *Daemon) dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	switch env.Op {
	case ipc.OpStatus:
		return d.handleStatus(env)

	case ipc.OpVaultInit:
		return d.handleVaultInit(ctx, env)
	case ipc.OpVaultUnlock:
		return d.handleVaultUnlock(env)
	case ipc.OpVaultLock:
		return d.handleVaultLock(env)
	case ipc.OpVaultList:
		return d.handleVaultList(env)
	case ipc.OpVaultDelete:
		return d.handleVaultDelete(ctx, env)
	case ipc.OpVaultPasswd:
		return d.handleVaultPasswd(ctx, env)
	case ipc.OpVaultRename:
		return d.handleVaultRename(ctx, env)

	case ipc.OpProjectCreate:
		return d.handleProjectCreate(ctx, env)
	case ipc.OpProjectList:
		return d.handleProjectList(ctx, env)
	case ipc.OpProjectDelete:
		return d.handleProjectDelete(ctx, env)
	case ipc.OpProjectRename:
		return d.handleProjectRename(ctx, env)

	case ipc.OpEnvCreate:
		return d.handleEnvCreate(ctx, env)
	case ipc.OpEnvList:
		return d.handleEnvList(ctx, env)
	case ipc.OpEnvDelete:
		return d.handleEnvDelete(ctx, env)
	case ipc.OpEnvClear:
		return d.handleEnvClear(ctx, env)
	case ipc.OpEnvRename:
		return d.handleEnvRename(ctx, env)

	case ipc.OpPut:
		return d.handlePut(ctx, env)
	case ipc.OpGet:
		return d.handleGet(ctx, env)
	case ipc.OpList:
		return d.handleList(ctx, env)
	case ipc.OpDelete:
		return d.handleDelete(ctx, env)
	case ipc.OpRename:
		return d.handleRename(ctx, env)

	case ipc.OpAuditTail:
		return d.handleAuditTail(ctx, env)
	case ipc.OpAuditVerify:
		return d.handleAuditVerify(ctx, env)
	case ipc.OpDoctor:
		return d.handleDoctor(ctx, env)
	case ipc.OpTrustList:
		return d.handleTrustList(env)
	case ipc.OpTrustRemove:
		return d.handleTrustRemove(env)
	case ipc.OpTrustGrant:
		return d.handleTrustGrant(ctx, env)
	case ipc.OpTrustVerify:
		return d.handleTrustVerify(ctx, env)
	case ipc.OpBynWrite:
		return d.handleBynWrite(ctx, env)
	case ipc.OpFSListDir:
		return d.handleListDir(env)
	case ipc.OpPasskeyRegisterBegin:
		return d.handlePasskeyRegisterBegin(ctx, env)
	case ipc.OpPasskeyRegisterFinish:
		return d.handlePasskeyRegisterFinish(ctx, env)
	case ipc.OpPasskeyAuthBegin:
		return d.handlePasskeyAuthBegin(ctx, env)
	case ipc.OpPasskeyAuthFinish:
		return d.handlePasskeyAuthFinish(ctx, env)
	case ipc.OpPasskeyList:
		return d.handlePasskeyList(ctx, env)
	case ipc.OpPasskeyRemove:
		return d.handlePasskeyRemove(ctx, env)

	default:
		return ipc.NewError(env.ID, ipc.CodeUnknownOp,
			fmt.Sprintf("unknown op %q", env.Op), "")
	}
}

// ---- Status ------------------------------------------------------------

func (d *Daemon) handleStatus(env *ipc.Envelope) *ipc.Envelope {
	summaries := d.buildVaultSummaries()
	resp, err := ipc.NewResponse(env.ID, ipc.StatusResp{
		Version:     d.cfg.Version,
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		SocketPath:  d.socketPath,
		StartedAt:   d.startedAt,
		Vaults:      summaries,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// buildVaultSummaries enumerates every vault on disk and reports its
// state. LastActive is suppressed for locked vaults (security finding
// from the design review: locked-vault timing is not exposed).
func (d *Daemon) buildVaultSummaries() []ipc.VaultSummary {
	names, _ := d.allVaultsOnDisk()
	known := make(map[string]bool, len(names))
	for _, n := range names {
		known[n] = true
	}
	// Include in-memory vaults too (covers the brief window between
	// vault.init and the directory entry being discoverable in a
	// concurrent walk).
	d.vaultsMu.RLock()
	for n := range d.vaults {
		known[n] = true
	}
	d.vaultsMu.RUnlock()

	out := make([]ipc.VaultSummary, 0, len(known))
	for name := range known {
		s := ipc.VaultSummary{Name: name, Initialized: true}
		if e := d.lookupVault(name); e != nil {
			s.Locked = e.store.IsLocked()
			if !s.Locked {
				if ns := e.lastActive.Load(); ns != 0 {
					t := time.Unix(0, ns).UTC()
					s.LastActive = &t
				}
			}
		} else {
			s.Locked = true
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- Vault lifecycle ---------------------------------------------------

func (d *Daemon) handleVaultInit(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultInitReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	if len(req.Password) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "empty password", "")
	}
	name := defaultIfEmpty(req.Name, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}

	st, err := vault.Init(ctx, d.cfg.Dir, name, req.Password)
	if err != nil {
		if errors.Is(err, vault.ErrAlreadyInit) {
			return ipc.NewError(env.ID, ipc.CodeAlreadyInit,
				fmt.Sprintf("vault %q already initialized", name),
				"`byn unlock` to open it")
		}
		return internalErr(env.ID, err)
	}
	if _, err := d.adoptVault(ctx, name, st); err != nil {
		return internalErr(env.ID, err)
	}

	resp, err := ipc.NewResponse(env.ID, ipc.VaultInitResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleVaultUnlock(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultUnlockReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	name := defaultIfEmpty(req.Name, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}

	if le := d.rateLimitCheck(env.ID); le != nil {
		return le
	}

	// Open or look up the vault. Open errors fall under the
	// existence-oracle defense — same wrong_password response.
	ctx := d.handlerCtx()
	entry, err := d.openVault(ctx, name)
	if err != nil {
		_ = d.limiter.RecordFailure()
		return ipc.NewError(env.ID, ipc.CodeWrongPassword,
			"could not unlock vault",
			"verify password, or `byn init` if no vault exists")
	}
	if err := entry.store.Unlock(req.Password); err != nil {
		_ = d.limiter.RecordFailure()
		d.auditEmit(ctx, name, audit.Event{
			Op:        "vault.unlock",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeWrongPassword),
		})
		return ipc.NewError(env.ID, ipc.CodeWrongPassword,
			"could not unlock vault", "verify password and retry")
	}
	_ = d.limiter.RecordSuccess()
	entry.touch()
	d.auditEmit(ctx, name, audit.Event{
		Op:      "vault.unlock",
		Outcome: audit.OutcomeOK,
	})

	resp, err := ipc.NewResponse(env.ID, ipc.VaultUnlockResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleVaultLock(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultLockReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	locked := 0
	if req.Name == "*" {
		d.vaultsMu.RLock()
		entries := make([]*vaultEntry, 0, len(d.vaults))
		for _, e := range d.vaults {
			entries = append(entries, e)
		}
		d.vaultsMu.RUnlock()
		for _, e := range entries {
			if !e.store.IsLocked() {
				e.store.Lock()
				locked++
			}
		}
	} else {
		name := defaultIfEmpty(req.Name, vault.DefaultVaultName)
		if err := vault.ValidateVaultName(name); err != nil {
			return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
		}
		if e := d.lookupVault(name); e != nil && !e.store.IsLocked() {
			e.store.Lock()
			locked = 1
		}
	}
	resp, err := ipc.NewResponse(env.ID, ipc.VaultLockResp{Locked: locked})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleVaultList(env *ipc.Envelope) *ipc.Envelope {
	summaries := d.buildVaultSummaries()
	resp, err := ipc.NewResponse(env.ID, ipc.VaultListResp{Vaults: summaries})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleVaultDelete securely removes a vault and all its data. The default
// vault is protected. A locked vault can still be deleted by supplying the
// password (verified, never unlocked) — see authorizeMutationWhileLocked.
func (d *Daemon) handleVaultDelete(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultDeleteReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	name := defaultIfEmpty(req.Name, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	if name == vault.DefaultVaultName {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"refusing to delete the default vault",
			"the default vault must always exist")
	}
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, name, st, req.Password); le != nil {
		return le
	}
	// Record the deletion BEFORE teardown: the audit log lives outside the
	// vault directory, so this leaves a forensic trail that survives the
	// wipe. Emit while the vault entry (and its auditor) still exists.
	d.auditEmit(ctx, name, audit.Event{Op: "vault.delete", Outcome: audit.OutcomeOK})
	// Evict the in-memory store (closes the DB, zeroes any key), then wipe
	// the on-disk data (overwrites wrapped.key, removes the directory).
	d.removeVault(name)
	if err := vault.Destroy(d.cfg.Dir, name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.VaultDeleteResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleVaultPasswd changes a vault's master password by re-wrapping the
// vault key. The old password authorizes the change and is rate-limited like
// unlock; the vault's data and lock state are unchanged.
func (d *Daemon) handleVaultPasswd(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultPasswdReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.OldPassword)
	defer zero(req.NewPassword)
	name := defaultIfEmpty(req.Name, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	if len(req.NewPassword) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "new password must not be empty", "")
	}
	// Rate-limit like unlock — this verifies the current password.
	if le := d.rateLimitCheck(env.ID); le != nil {
		return le
	}
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	if err := st.ChangePassword(req.OldPassword, req.NewPassword); err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			_ = d.limiter.RecordFailure()
			d.auditEmit(ctx, name, audit.Event{
				Op:        "vault.passwd",
				Outcome:   audit.OutcomeDenied,
				ErrorCode: string(ipc.CodeWrongPassword),
			})
			return ipc.NewError(env.ID, ipc.CodeWrongPassword,
				"current password is incorrect", "verify the current password and retry")
		}
		return mapVaultErr(env.ID, err)
	}
	_ = d.limiter.RecordSuccess()
	d.auditEmit(ctx, name, audit.Event{Op: "vault.passwd", Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.VaultPasswdResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleVaultRename renames a vault (and its audit trail) on disk. Like a
// delete it touches names only, so a locked vault is renameable with the
// password. Renaming evicts the in-memory store, so the vault is LEFT LOCKED
// (its key is dropped) — the caller must unlock again to keep using it.
func (d *Daemon) handleVaultRename(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.VaultRenameReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	oldName := defaultIfEmpty(req.OldName, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(oldName); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	if err := vault.ValidateVaultName(req.NewName); err != nil {
		return ipc.NewError(env.ID, ipc.CodeBadName, err.Error(), "")
	}
	if oldName == vault.DefaultVaultName {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"the default vault cannot be renamed", "the default vault must always exist")
	}
	st, errEnv := d.storeForVault(env.ID, oldName)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, oldName, st, req.Password); le != nil {
		return le
	}
	// Record the rename in the OLD vault's audit log before teardown; the
	// audit dir is moved alongside the vault below, so the event follows.
	d.auditEmit(ctx, oldName, audit.Event{Op: "vault.rename", Outcome: audit.OutcomeOK})
	// Evict the in-memory store (closes the SQLite handle that pins the old
	// path) before moving the directory.
	d.removeVault(oldName)
	if err := vault.RenameVault(d.cfg.Dir, oldName, req.NewName); err != nil {
		return mapVaultErr(env.ID, err)
	}
	// Move the audit trail to follow the vault. Best-effort: a missing or
	// unmovable audit dir must not fail the rename.
	oldAudit := filepath.Join(d.cfg.Dir, "audit", oldName)
	newAudit := filepath.Join(d.cfg.Dir, "audit", req.NewName)
	if _, statErr := os.Stat(oldAudit); statErr == nil {
		_ = os.Rename(oldAudit, newAudit)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.VaultRenameResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// ---- Trust store -------------------------------------------------------

// handleTrustList returns the TOFU-approved `.byn` files. The store is
// global (not per-vault) and carries no secret values, so it needs no lock.
func (d *Daemon) handleTrustList(env *ipc.Envelope) *ipc.Envelope {
	store, err := trust.Load(d.cfg.Dir)
	if err != nil {
		return internalErr(env.ID, err)
	}
	entries := make([]ipc.TrustEntry, 0, len(store.Records))
	for _, r := range store.Records {
		entries = append(entries, ipc.TrustEntry{Path: r.Path, SHA256: r.SHA256})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.TrustListResp{Entries: entries})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleTrustRemove revokes trust for an exact stored path.
func (d *Daemon) handleTrustRemove(env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustRemoveReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}
	removed, err := trust.Remove(d.cfg.Dir, req.Path)
	if err != nil {
		return internalErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.TrustRemoveResp{Removed: removed})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleTrustGrant records TOFU trust for a `.byn`, gated by the master
// password of the target vault. Unlike a delete, the password is required even
// when the vault is already unlocked: granting trust is a proof-of-presence
// action, so an ambient unlocked session is never sufficient consent. The
// daemon reads + hashes the file itself (authoritative), so a caller cannot
// record a fingerprint for content it never actually presented.
func (d *Daemon) handleTrustGrant(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustGrantReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}
	if len(req.Password) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"granting trust requires the master password",
			"run `byn trust` from a terminal so byn can prompt for it")
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	// Always verify — even an unlocked vault must re-prove presence here.
	if le := d.authorizeWithPassword(ctx, env.ID, name, st, req.Password); le != nil {
		return le
	}
	body, rerr := os.ReadFile(req.Path) // #nosec G304 -- user-named; daemon runs as the same user
	if rerr != nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("read %s: %v", req.Path, rerr), "check the path and retry")
	}
	// Mint both MACs (vk from the just-verified password so it works on a
	// locked vault, fp from the machine key) and record {canon path, hash}.
	canon, hash, changed, gerr := d.putTrustRecord(st, name, req.Path, body, req.Password)
	if gerr != nil {
		return internalErr(env.ID, gerr)
	}
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.TrustGrantResp{Path: canon, SHA256: hash, Changed: changed})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleTrustVerify checks a `.byn` against the hardened trust store. The
// fp-MAC (machine) layer is verified whenever its key is available — including
// while the vault is locked, which is what gates discovery. The vk-MAC
// (vault-key) layer is verified only when the target vault is unlocked, the
// use-time gate before a value flows. It mutates nothing.
func (d *Daemon) handleTrustVerify(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustVerifyReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	// auditExec records the exec authorization decision in the caller's vault
	// log: which .byn, which command, and whether trust authorized the
	// injection (ok) or blocked it (denied). This is what makes a
	// .byn-authorized injection traceable to its command when reading logs.
	auditExec := func(path, status string) {
		outcome := audit.OutcomeDenied
		if status == string(trust.VerifyTrusted) {
			outcome = audit.OutcomeOK
		}
		d.auditEmit(ctx, name, audit.Event{
			Op: "exec", Outcome: outcome, BynPath: path, Command: req.Command,
		})
	}
	body, rerr := os.ReadFile(req.Path) // #nosec G304 -- user-named; daemon runs as the same user
	if rerr != nil {
		// File gone or unreadable: nothing to trust.
		auditExec(trust.Canonicalize(req.Path), string(trust.VerifyUntrusted))
		resp, err := ipc.NewResponse(env.ID, ipc.TrustVerifyResp{
			Path: req.Path, Status: string(trust.VerifyUntrusted),
		})
		if err != nil {
			return internalErr(env.ID, err)
		}
		return resp
	}
	canon := trust.Canonicalize(req.Path)
	hash := trust.Hash(body)

	// vk-MAC key only when the target vault is unlocked (use-time check); while
	// locked the fp-MAC alone gates discovery.
	var vkKey []byte
	if st, errEnv := d.storeForVault(env.ID, name); errEnv == nil && !st.IsLocked() {
		if k, derr := st.DeriveSubkey(trust.VKMACKeyInfo); derr == nil {
			vkKey = k
			defer zeroBytes(vkKey)
		}
	}

	status, vkChecked, verr := trust.Verify(d.cfg.Dir, canon, hash, d.fpMACKey, vkKey)
	if verr != nil {
		return internalErr(env.ID, verr)
	}
	auditExec(canon, string(status))
	resp, err := ipc.NewResponse(env.ID, ipc.TrustVerifyResp{
		Path: canon, Status: string(status), VKChecked: vkChecked,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// zeroBytes wipes a derived-key buffer in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ---- Project CRUD ------------------------------------------------------

func (d *Daemon) handleProjectCreate(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ProjectCreateReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, errEnv := d.unlockedStoreForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if err := st.CreateProject(ctx, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ProjectCreateResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleProjectList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ProjectListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	projects, err := st.ListProjects(ctx)
	if err != nil {
		return internalErr(env.ID, err)
	}
	out := make([]ipc.ProjectInfo, 0, len(projects))
	for _, p := range projects {
		out = append(out, ipc.ProjectInfo{
			Name:      p.Name,
			CreatedAt: p.CreatedAt,
			UpdatedAt: p.UpdatedAt,
		})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ProjectListResp{Projects: out})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleProjectDelete(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ProjectDeleteReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Vault, st, req.Password); le != nil {
		return le
	}
	if err := st.DeleteProject(ctx, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ProjectDeleteResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleProjectRename(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ProjectRenameReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Vault, st, req.Password); le != nil {
		return le
	}
	if err := st.RenameProject(ctx, req.OldName, req.NewName); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ProjectRenameResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// ---- Env CRUD ----------------------------------------------------------

func (d *Daemon) handleEnvCreate(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.EnvCreateReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, errEnv := d.unlockedStoreForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	if err := st.CreateEnv(ctx, project, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.EnvCreateResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleEnvList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.EnvListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	envs, err := st.ListEnvs(ctx, project)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	out := make([]ipc.EnvInfo, 0, len(envs))
	for _, e := range envs {
		out = append(out, ipc.EnvInfo{
			Name:      e.Name,
			IsDefault: e.IsDefault,
			CreatedAt: e.CreatedAt,
			UpdatedAt: e.UpdatedAt,
		})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.EnvListResp{Envs: out})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleEnvDelete(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.EnvDeleteReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Vault, st, req.Password); le != nil {
		return le
	}
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	if err := st.DeleteEnv(ctx, project, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.EnvDeleteResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleEnvRename(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.EnvRenameReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Vault, st, req.Password); le != nil {
		return le
	}
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	if err := st.RenameEnv(ctx, project, req.OldName, req.NewName); err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.EnvRenameResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// ---- Data-plane (env-var CRUD) -----------------------------------------

func (d *Daemon) handlePut(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.PutReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "put", errEnv)
		return errEnv
	}
	var resp *ipc.Envelope
	if err := st.PutEnvVar(ctx, scope, req.Name, req.Value, vault.PutOpt{CreateOnly: req.CreateOnly}); err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, err := ipc.NewResponse(env.ID, ipc.PutResp{})
		if err != nil {
			resp = internalErr(env.ID, err)
		} else {
			resp = out
		}
	}
	d.auditPlane(ctx, req.Scope, "env_var", req.Name, "put", resp)
	return resp
}

func (d *Daemon) handleGet(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.GetReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "get", errEnv)
		return errEnv
	}
	var resp *ipc.Envelope
	got, err := st.GetEnvVar(ctx, scope, req.Name)
	if err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, err := ipc.NewResponse(env.ID, ipc.GetResp{
			Name:      got.Name,
			Value:     got.Value,
			Source:    got.Source.String(),
			CreatedAt: got.CreatedAt,
			UpdatedAt: got.UpdatedAt,
		})
		if err != nil {
			resp = internalErr(env.ID, err)
		} else {
			resp = out
		}
	}
	d.auditPlane(ctx, req.Scope, "env_var", req.Name, "get", resp)
	return resp
}

func (d *Daemon) handleList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	out := make([]ipc.SecretMeta, 0, len(infos))
	for _, m := range infos {
		out = append(out, ipc.SecretMeta{
			Name:      m.Name,
			Source:    m.Source.String(),
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ListResp{Secrets: out})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

func (d *Daemon) handleDelete(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.DeleteReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "delete", errEnv)
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Scope.Vault, st, req.Password); le != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "delete", le)
		return le
	}
	var resp *ipc.Envelope
	if err := st.DeleteEnvVar(ctx, scope, req.Name); err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, err := ipc.NewResponse(env.ID, ipc.DeleteResp{})
		if err != nil {
			resp = internalErr(env.ID, err)
		} else {
			resp = out
		}
	}
	d.auditPlane(ctx, req.Scope, "env_var", req.Name, "delete", resp)
	return resp
}

// handleEnvClear deletes ALL env-vars in the scope's env (the env is kept),
// gated by the master password like a delete. Returns the count removed.
func (d *Daemon) handleEnvClear(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.EnvClearReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", "*", "clear", errEnv)
		return errEnv
	}
	if le := d.authorizeMutationWhileLocked(ctx, env.ID, req.Scope.Vault, st, req.Password); le != nil {
		d.auditPlane(ctx, req.Scope, "env_var", "*", "clear", le)
		return le
	}
	var resp *ipc.Envelope
	if n, err := st.ClearEnvVars(ctx, scope); err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, oerr := ipc.NewResponse(env.ID, ipc.EnvClearResp{Deleted: n})
		if oerr != nil {
			resp = internalErr(env.ID, oerr)
		} else {
			resp = out
		}
	}
	d.auditPlane(ctx, req.Scope, "env_var", "*", "clear", resp)
	return resp
}

func (d *Daemon) handleRename(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.RenameReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.OldName, "rename", errEnv)
		return errEnv
	}
	if le := requireUnlocked(env.ID, st); le != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.OldName, "rename", le)
		return le
	}
	var resp *ipc.Envelope
	if err := st.RenameEnvVar(ctx, scope, req.OldName, req.NewName); err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, err := ipc.NewResponse(env.ID, ipc.RenameResp{})
		if err != nil {
			resp = internalErr(env.ID, err)
		} else {
			resp = out
		}
	}
	// Audit records the old name; the rename succeeded if outcome=ok.
	d.auditPlane(ctx, req.Scope, "env_var", req.OldName+"→"+req.NewName, "rename", resp)
	return resp
}

// ---- Scope / vault routing helpers -------------------------------------

// scopeFor resolves the wire-Scope to (store, vault.Scope) for the
// chosen vault. Returns an error envelope on missing/uninitialized
// vault.
func (d *Daemon) scopeFor(id string, s ipc.Scope) (*vault.Store, vault.Scope, *ipc.Envelope) {
	vaultName := defaultIfEmpty(s.Vault, vault.DefaultVaultName)
	project := defaultIfEmpty(s.Project, vault.DefaultProjectName)
	envName := defaultIfEmpty(s.Env, vault.DefaultEnvName)

	st, errEnv := d.storeForVault(id, vaultName)
	if errEnv != nil {
		return nil, vault.Scope{}, errEnv
	}
	// NOTE: no lock check here. `list` (entry NAMES, no values) MUST work
	// while locked — that is byn's core promise: agents can always see
	// which env-vars exist, never the values. `get` (a value) and the
	// mutations (`put`/`delete`/`rename`) gate on lock — put/get via the
	// key, delete/rename via an explicit check in their handlers.
	return st, vault.Scope{Project: project, Env: envName}, nil
}

// requireUnlocked returns a CodeLocked envelope when st is locked, for the
// key-free entry mutations (rename) that wouldn't otherwise fail.
func requireUnlocked(id string, st *vault.Store) *ipc.Envelope {
	if st.IsLocked() {
		return ipc.NewError(id, ipc.CodeLocked, "vault is locked", "byn unlock")
	}
	return nil
}

// rateLimitCheck returns a CodeRateLimited envelope when the shared auth
// limiter is in backoff, or nil when an attempt is allowed right now. Used
// by every password-verifying op: unlock, authorized delete, and passwd.
func (d *Daemon) rateLimitCheck(id string) *ipc.Envelope {
	err := d.limiter.Check()
	if err == nil {
		return nil
	}
	var rae *auth.RetryAfterError
	if errors.As(err, &rae) {
		return ipc.NewError(id, ipc.CodeRateLimited, rae.Error(),
			fmt.Sprintf("retry after %s", rae.RetryAfter.Round(time.Second)))
	}
	return ipc.NewError(id, ipc.CodeRateLimited, err.Error(), "")
}

// authorizeMutationWhileLocked authorizes a key-free mutation (a delete) on
// a possibly-locked vault. If st is already unlocked it returns nil. If st
// is locked it requires a correct password, which it verifies against the
// wrapped key WITHOUT unlocking the vault — so a delete never exposes the
// rest of the vault to a process sniffing daemon memory. It is rate-limited
// exactly like unlock. Returns:
//   - nil               authorized (unlocked, or locked + correct password)
//   - CodeLocked        locked and no password supplied (client should prompt)
//   - CodeRateLimited   too many recent failures
//   - CodeWrongPassword locked and the password was wrong
func (d *Daemon) authorizeMutationWhileLocked(ctx context.Context, id, vaultName string, st *vault.Store, password []byte) *ipc.Envelope {
	if !st.IsLocked() {
		return nil
	}
	if len(password) == 0 {
		return ipc.NewError(id, ipc.CodeLocked, "vault is locked",
			"unlock the vault, or supply the password to authorize this delete")
	}
	if le := d.rateLimitCheck(id); le != nil {
		return le
	}
	if err := st.VerifyPassword(password); err != nil {
		_ = d.limiter.RecordFailure()
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        "vault.authorize",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeWrongPassword),
		})
		return ipc.NewError(id, ipc.CodeWrongPassword,
			"could not authorize delete", "verify password and retry")
	}
	_ = d.limiter.RecordSuccess()
	return nil
}

// authorizeWithPassword verifies the master password against st's wrapped key
// WITHOUT unlocking the vault, regardless of the current lock state. Unlike
// authorizeMutationWhileLocked (which short-circuits when the vault is already
// unlocked), this ALWAYS requires a correct password — used for
// proof-of-presence actions like granting trust, where an ambient unlocked
// session is not consent. Rate-limited exactly like unlock. The caller
// guarantees password is non-empty.
func (d *Daemon) authorizeWithPassword(ctx context.Context, id, vaultName string, st *vault.Store, password []byte) *ipc.Envelope {
	if le := d.rateLimitCheck(id); le != nil {
		return le
	}
	if err := st.VerifyPassword(password); err != nil {
		_ = d.limiter.RecordFailure()
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        "vault.authorize",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeWrongPassword),
		})
		return ipc.NewError(id, ipc.CodeWrongPassword,
			"could not authorize: wrong password", "verify the password and retry")
	}
	_ = d.limiter.RecordSuccess()
	return nil
}

// storeForVault returns the open *vault.Store for the named vault, or
// an error envelope. Vault name "" is treated as "default".
// unlockedStoreForVault is storeForVault plus a lock check. Structural
// mutations (project/env create, delete, rename) require the vault
// unlocked, per SPEC §4.2.2 — only specific metadata READS are allowed
// while a vault is locked. The list handlers keep using storeForVault.
func (d *Daemon) unlockedStoreForVault(id, name string) (*vault.Store, *ipc.Envelope) {
	st, errEnv := d.storeForVault(id, name)
	if errEnv != nil {
		return nil, errEnv
	}
	if st.IsLocked() {
		return nil, ipc.NewError(id, ipc.CodeLocked, "vault is locked", "byn unlock")
	}
	return st, nil
}

func (d *Daemon) storeForVault(id, name string) (*vault.Store, *ipc.Envelope) {
	name = defaultIfEmpty(name, vault.DefaultVaultName)
	if err := vault.ValidateVaultName(name); err != nil {
		return nil, ipc.NewError(id, ipc.CodeBadName, err.Error(), "")
	}
	entry, err := d.openVault(context.Background(), name)
	if err != nil {
		if errors.Is(err, vault.ErrNotInit) {
			return nil, ipc.NewError(id, ipc.CodeNotInit,
				fmt.Sprintf("vault %q is not initialized", name),
				"`byn init`")
		}
		if errors.Is(err, vault.ErrFingerprintMismatch) {
			return nil, ipc.NewError(id, ipc.CodeFingerprint,
				err.Error(),
				"investigate the wrapped key file before retrying")
		}
		return nil, internalErr(id, err)
	}
	return entry.store, nil
}

// touchVault updates lastActive on a successful data-plane op so the
// idle timer (Slice 4) sees activity.
func (d *Daemon) touchVault(rawName string) {
	name := defaultIfEmpty(rawName, vault.DefaultVaultName)
	if e := d.lookupVault(name); e != nil {
		e.touch()
	}
}

// ---- error mapping -----------------------------------------------------

// mapVaultErr converts a vault.Store error into an IPC error envelope
// with the right code and recovery hint.
func mapVaultErr(id string, err error) *ipc.Envelope {
	switch {
	case errors.Is(err, vault.ErrLocked):
		return ipc.NewError(id, ipc.CodeLocked, "vault is locked", "byn unlock")
	case errors.Is(err, vault.ErrNotFound):
		return ipc.NewError(id, ipc.CodeNotFound, "secret not found", "")
	case errors.Is(err, vault.ErrExists):
		return ipc.NewError(id, ipc.CodeAlreadyExists, "secret already exists", "")
	case errors.Is(err, vault.ErrBadName):
		return ipc.NewError(id, ipc.CodeBadName, "invalid secret name", "")
	case errors.Is(err, vault.ErrProjectNotFound):
		return ipc.NewError(id, ipc.CodeProjectNotFound, "project not found", "")
	case errors.Is(err, vault.ErrProjectExists):
		return ipc.NewError(id, ipc.CodeProjectExists, "project already exists", "")
	case errors.Is(err, vault.ErrBadProjectName):
		return ipc.NewError(id, ipc.CodeBadName, "invalid project name", "")
	case errors.Is(err, vault.ErrEnvNotFound):
		return ipc.NewError(id, ipc.CodeEnvNotFound, "env not found", "")
	case errors.Is(err, vault.ErrEnvExists):
		return ipc.NewError(id, ipc.CodeEnvExists, "env already exists", "")
	case errors.Is(err, vault.ErrVaultExists):
		return ipc.NewError(id, ipc.CodeVaultExists, "a vault with that name already exists", "")
	case errors.Is(err, vault.ErrProtectedVault):
		return ipc.NewError(id, ipc.CodeBadRequest, "the default vault cannot be renamed or deleted", "")
	case errors.Is(err, vault.ErrEnvProtected):
		return ipc.NewError(id, ipc.CodeEnvProtected,
			"the default env cannot be renamed or deleted", "")
	case errors.Is(err, vault.ErrBadEnvName):
		return ipc.NewError(id, ipc.CodeBadName, "invalid env name", "")
	default:
		return internalErr(id, err)
	}
}

func badRequest(id string, err error) *ipc.Envelope {
	return ipc.NewError(id, ipc.CodeBadRequest, err.Error(), "")
}

func internalErr(id string, err error) *ipc.Envelope {
	return ipc.NewError(id, ipc.CodeInternal, err.Error(), "")
}

// defaultIfEmpty returns def if s is empty, else s.
func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// auditEmit writes an event to the named vault's audit log. Silent on
// failure — audit failures must not block the user's operation. The
// daemon log will record any error in a future slice.
func (d *Daemon) auditEmit(ctx context.Context, vaultName string, ev audit.Event) {
	vaultName = defaultIfEmpty(vaultName, vault.DefaultVaultName)
	e := d.lookupVault(vaultName)
	if e == nil || e.auditor == nil {
		return
	}
	stampCaller(ctx, &ev)
	_, _ = e.auditor.Append(ctx, ev)
}

// auditPlane writes one audit event for a data-plane op. Centralizes
// the scope-to-event mapping so each handler is one line.
func (d *Daemon) auditPlane(ctx context.Context, scope ipc.Scope, kind, name, op string, resp *ipc.Envelope) {
	outcome, code := outcomeFor(resp)
	d.auditEmit(ctx, scope.Vault, audit.Event{
		Project:   defaultIfEmpty(scope.Project, vault.DefaultProjectName),
		Env:       defaultIfEmpty(scope.Env, vault.DefaultEnvName),
		Kind:      kind,
		EntryName: name,
		Op:        op,
		Outcome:   outcome,
		ErrorCode: code,
	})
}

// outcomeFor maps a dispatch result back to an audit outcome string
// based on the wire-error code (or absence thereof). Centralized so
// the data-plane handlers stay tight.
func outcomeFor(resp *ipc.Envelope) (outcome, code string) {
	if resp == nil || resp.Err == nil {
		return audit.OutcomeOK, ""
	}
	switch resp.Err.Code {
	case ipc.CodeNotFound, ipc.CodeProjectNotFound, ipc.CodeEnvNotFound, ipc.CodeVaultNotFound:
		return audit.OutcomeNotFound, string(resp.Err.Code)
	case ipc.CodeLocked, ipc.CodeWrongPassword, ipc.CodeRateLimited, ipc.CodeAlreadyExists,
		ipc.CodeAlreadyInit, ipc.CodeBadName, ipc.CodeBadRequest, ipc.CodeEnvProtected:
		return audit.OutcomeDenied, string(resp.Err.Code)
	default:
		return audit.OutcomeError, string(resp.Err.Code)
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
