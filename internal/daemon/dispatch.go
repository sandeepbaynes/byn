package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/fdpass"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// connReadTimeout caps how long the daemon will wait for a single
// envelope on an accepted connection.
const connReadTimeout = 30 * time.Second

func (d *Daemon) handleConn(conn net.Conn) {
	// Peer-UID enforcement (and capture the peer PID for the audit trail).
	uid, pid, err := peerCred(conn)
	if err != nil && !errors.Is(err, ErrNotUnix) {
		_ = ipc.WriteFrame(conn, ipc.NewError("", ipc.CodeInternal,
			fmt.Sprintf("could not verify peer credentials: %v", err), ""))
		return
	}
	// Two peer classes are allowed: the human OWNER (all data-plane ops), and the
	// privsep exec HELPER — root or _byn-exec — which may ONLY redeem an exec token
	// (Option A). ErrNotUnix (in-proc/tests) bypasses the check. Any other UID is
	// rejected up front.
	peerKnown := err == nil
	peerIsHelper := peerKnown && d.isExecHelperUID(uid)
	if peerKnown && uid != d.ownerUID && !peerIsHelper {
		_ = ipc.WriteFrame(conn, ipc.NewError("", ipc.CodeBadRequest,
			fmt.Sprintf("connection from uid %d rejected (owner uid is %d)", uid, d.ownerUID),
			""))
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

	// Privsep redemption gate (Option A): exec.redeem is reachable ONLY by the
	// exec helper (root/_byn-exec) — never the owner-UID CLI, which would leak the
	// curated secrets. Conversely a helper peer may ONLY redeem; it cannot reach
	// any other op. ErrNotUnix (in-proc/tests) is exempt here — those paths gate on
	// the caller UID inside handleExecRedeem instead.
	if peerKnown {
		isOwner := uid == d.ownerUID
		if env.Op == ipc.OpExecRedeem && !peerIsHelper {
			_ = ipc.WriteFrame(conn, ipc.NewError(env.ID, ipc.CodeBadRequest,
				"exec.redeem is restricted to the privsep exec helper", ""))
			return
		}
		if peerIsHelper && !isOwner && env.Op != ipc.OpExecRedeem {
			_ = ipc.WriteFrame(conn, ipc.NewError(env.ID, ipc.CodeBadRequest,
				"this peer may only redeem exec tokens", ""))
			return
		}
	}

	// Per-request context derived from the daemon's root context, so
	// in-flight SQLite + audit calls observe Shutdown. Falls back to
	// context.Background() if Start hasn't established a root yet
	// (e.g. during tests that drive dispatch directly).
	root := d.rootCtx
	if root == nil {
		root = context.Background()
	}
	if err == nil {
		root = withCaller(root, socketCaller(uid, pid, env.Session))
	}

	// exec.spawn carries its child's three stdio fds out-of-band: right after
	// the request frame the CLI SendFDs([]int{0,1,2}) over this same connection.
	// Receive them HERE (before dispatch), stash them in the request context for
	// handleExecSpawn, and close the daemon's copies after dispatch returns. The
	// spawner dups what it needs (privsep dupStdio), so closing our originals
	// post-dispatch frees them without affecting the running child. Every other
	// op is untouched — only exec.spawn does the fd dance.
	if err == nil && env.Op == ipc.OpExecSpawn {
		fds, rcvErr := recvExecSpawnFDs(conn)
		if rcvErr != nil {
			_ = ipc.WriteFrame(conn, ipc.NewError(env.ID, ipc.CodeBadRequest,
				fmt.Sprintf("exec.spawn: receive stdio fds: %v", rcvErr), ""))
			return
		}
		defer fdpass.CloseAll(fds)
		root = withExecSpawnFDs(root, fds[0], fds[1], fds[2])
	}

	resp := d.dispatch(root, env)
	_ = ipc.WriteFrame(conn, resp)
}

// execSpawnFDTimeout bounds how long the daemon waits for the client's
// SCM_RIGHTS control message after the exec.spawn request frame. A client that
// sends a frame but never the fds must not wedge the handler — the deadline
// surfaces as a non-EAGAIN error from rc.Read and we fail cleanly.
const execSpawnFDTimeout = 5 * time.Second

// recvExecSpawnFDs receives EXACTLY the three stdio fds the CLI sent via
// SCM_RIGHTS right after the request frame. The returned fds are the daemon's
// own copies (the kernel dup'd them into our table); the caller closes them
// after dispatch.
//
// The receive is driven through the conn's SyscallConn().Read so it is
// netpoller-aware. The request frame's bytes can wake ReadEnvelope before the
// separate control message lands; a raw Recvmsg on the runtime's non-blocking
// fd would then return EAGAIN and spuriously fail a valid exec (~1-in-10 under
// load). rc.Read parks on the netpoller until the fd is readable and retries
// the callback, so we WAIT for the control message instead of racing it. The
// callback returns false on EAGAIN to keep waiting; any other outcome (success
// or a real error) completes the read. A fresh read deadline bounds the wait
// (the handler cleared the long-op deadline earlier), so a client that sends a
// frame but never the fds times out cleanly rather than hanging.
func recvExecSpawnFDs(conn net.Conn) ([]int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("conn does not support fd passing")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(execSpawnFDTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var fds []int
	var opErr error
	rerr := rc.Read(func(fd uintptr) bool {
		fds, opErr = fdpass.RecvFDs(int(fd), 3)
		// Returning false keeps waiting when the control message hasn't arrived
		// yet; the netpoller re-invokes us when the fd becomes readable (or the
		// deadline fires, which surfaces as a non-EAGAIN error from rc.Read).
		return !errors.Is(opErr, syscall.EAGAIN)
	})
	if rerr != nil {
		return nil, rerr // deadline/timeout or runtime error
	}
	return fds, opErr
}

// Dispatch routes one IPC envelope in-process and returns the response.
// It is the entry point the embedded web UI uses, so browser requests go
// through the exact same handlers (scope resolution, audit, lock checks)
// as Unix-socket clients.
func (d *Daemon) Dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	// Portal requests run in-process; tag them so the audit trail records
	// "portal" (browser) rather than a Unix-socket peer.
	// Envelope.Session is threaded into callerInfo so Task-2 gate helpers can
	// read the presented token from ctx via callerSession(ctx).
	return d.dispatch(withCaller(ctx, d.portalCaller(env.Session)), env)
}

// dispatch routes one envelope to the right handler.
func (d *Daemon) dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	switch env.Op {
	case ipc.OpStatus:
		return d.handleStatus(ctx, env)

	case ipc.OpVaultInit:
		return d.handleVaultInit(ctx, env)
	case ipc.OpVaultUnlock:
		return d.handleVaultUnlock(ctx, env)
	case ipc.OpVaultLock:
		return d.handleVaultLock(ctx, env)
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

	case ipc.OpExecFetch:
		return d.handleExecFetch(ctx, env)
	case ipc.OpExecSpawn:
		return d.handleExecSpawn(ctx, env)
	case ipc.OpExecAuthorize:
		return d.handleExecAuthorize(ctx, env)
	case ipc.OpExecRedeem:
		return d.handleExecRedeem(ctx, env)

	case ipc.OpAuditTail:
		return d.handleAuditTail(ctx, env)
	case ipc.OpAuditVerify:
		return d.handleAuditVerify(ctx, env)
	case ipc.OpAuditReseal:
		return d.handleAuditReseal(ctx, env)
	case ipc.OpDoctor:
		return d.handleDoctor(ctx, env)
	case ipc.OpTrustList:
		return d.handleTrustList(env)
	case ipc.OpTrustRemove:
		return d.handleTrustRemove(env)
	case ipc.OpTrustGrant:
		return d.handleTrustGrant(ctx, env)
	case ipc.OpTrustGrantBulk:
		return d.handleTrustGrantBulk(ctx, env)
	case ipc.OpTrustVerify:
		return d.handleTrustVerify(ctx, env)
	case ipc.OpTrustDiff:
		return d.handleTrustDiff(ctx, env)
	case ipc.OpBynWrite:
		return d.handleBynWrite(ctx, env)
	case ipc.OpBynValidate:
		return d.handleBynValidate(ctx, env)
	case ipc.OpBynSimulate:
		return d.handleBynSimulate(ctx, env)
	case ipc.OpBynRead:
		return d.handleBynRead(ctx, env)
	case ipc.OpConfigGet:
		return d.handleConfigGet(ctx, env)
	case ipc.OpConfigSet:
		return d.handleConfigSet(ctx, env)
	case ipc.OpConfigValidate:
		return d.handleConfigValidate(ctx, env)
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

	case ipc.OpDaemonReload:
		return d.handleDaemonReload(env)
	case ipc.OpDaemonRestart:
		return d.handleDaemonRestart(env)

	case ipc.OpWebBootstrap:
		return d.handleWebBootstrap(env)

	case ipc.OpConfigAuth:
		return d.handleConfigAuth(env)

	case ipc.OpSessionEnd:
		return d.handleSessionEnd(ctx, env)

	default:
		return ipc.NewError(env.ID, ipc.CodeUnknownOp,
			fmt.Sprintf("unknown op %q", env.Op), "")
	}
}

// ---- Status ------------------------------------------------------------

func (d *Daemon) handleStatus(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	summaries := d.buildVaultSummariesForCaller(ctx)

	// FDA check: only meaningful on macOS when privsep is active, because
	// then the daemon runs as _byn (not the owner) and macOS TCC applies.
	// When privsep is off the daemon runs as the owner, who inherits the
	// Terminal's TCC grant, so no separate FDA is needed.
	var fdaGranted *bool
	if runtime.GOOS == "darwin" && d.cfg.Privsep {
		v := privsep.CheckFDA()
		fdaGranted = &v
	}

	resp, err := ipc.NewResponse(env.ID, ipc.StatusResp{
		Version:     d.cfg.Version,
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		SocketPath:  d.socketPath,
		StartedAt:   d.startedAt,
		Vaults:      summaries,
		UIEnabled:   d.cfg.UIEnabled,
		UIPort:      d.cfg.UIPort,
		Privsep:     d.cfg.Privsep,
		FDAGranted:  fdaGranted,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// buildVaultSummariesForCaller builds the vault summaries and, when the caller
// has an active session token in ctx, annotates each vault with SessionActive
// and SessionExpiresAt (read-only — does not slide LastUsed).
func (d *Daemon) buildVaultSummariesForCaller(ctx context.Context) []ipc.VaultSummary {
	summaries := d.buildVaultSummaries()
	ci := callerFrom(ctx)
	tok := string(callerSession(ctx))
	if tok == "" {
		return summaries
	}
	now := time.Now()
	for i := range summaries {
		active, exp := d.sessions.sessionInfo(tok, summaries[i].Name, ci.UID, ci.TTYDev, now)
		if active {
			summaries[i].SessionActive = true
			summaries[i].SessionExpiresAt = exp
		}
	}
	return summaries
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

func (d *Daemon) handleVaultUnlock(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
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
	// ctx carries the caller identity (set by handleConn / Dispatch).
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

	// Mint a session for this unlock. The caller identity (UID + TTYDev) is
	// taken from the request context (set in handleConn / Dispatch).
	ci := callerFrom(ctx)
	var sessionToken []byte
	if ci.Surface == "portal" {
		tok := d.mintSessionForPortal(name, time.Now())
		sessionToken = []byte(tok)
	} else {
		tok := d.mintSessionForSocket(name, ci.UID, ci.PID, time.Now())
		sessionToken = []byte(tok)
	}

	resp, err := ipc.NewResponse(env.ID, ipc.VaultUnlockResp{SessionToken: sessionToken})
	if err != nil {
		return internalErr(env.ID, err)
	}
	// Also carry the token in the envelope header so callers can extract it
	// without decoding the response body.
	resp.Session = sessionToken
	return resp
}

func (d *Daemon) handleVaultLock(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
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
				// End all sessions for this vault — lock is explicit revocation.
				// Emit one session.end audit event per ended session (surface logged,
				// token never logged).
				for _, surface := range d.sessions.endVault(e.name) {
					d.auditEmit(ctx, e.name, audit.Event{
						Op: string(ipc.OpSessionEnd), Outcome: audit.OutcomeOK,
						CallerSurface: surface,
					})
				}
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
			// End all sessions for this vault — lock is explicit revocation.
			for _, surface := range d.sessions.endVault(name) {
				d.auditEmit(ctx, name, audit.Event{
					Op: string(ipc.OpSessionEnd), Outcome: audit.OutcomeOK,
					CallerSurface: surface,
				})
			}
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
// vault is protected. Fresh credentials (master password OR a passkey presence
// token) are ALWAYS required — a session is not sufficient for this destructive
// operation. This mirrors the trust-grant proof-of-presence precedent: destroying
// data demands explicit intent, not ambient authorization. A locked vault is
// therefore also covered: the password must be supplied regardless of lock state.
// The portal's apiWithAuth handles the step-up transparently on auth_required.
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
	// vault.delete is ALWAYS fresh-credentials — session explicitly insufficient.
	// Destructive, irreversible action: proof-of-presence required regardless of
	// whether the vault is locked or an active session exists.
	if le := d.authorizeActionAlways(ctx, env.ID, name, st,
		"vault delete requires authorization (sessions do not authorize vault deletion)",
		"supply the master password to authorize this destructive action",
		req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, name, audit.Event{
			Op:        "vault.delete",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
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
	defer zero(req.PresenceToken)
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
	if le := d.authorizeAction(ctx, env.ID, oldName, vault.Scope{}, st, "update", req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, oldName, audit.Event{
			Op:        "vault.rename",
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
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
	// Privsep: best-effort revoke the exec service user's ACL on the project dir
	// when a record was actually removed (no-op when privsep is off; never fails
	// untrust). Mirrors grantProjectACL at trust time.
	if removed {
		d.revokeProjectACL(req.Path)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.TrustRemoveResp{Removed: removed})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleTrustGrant records TOFU trust for a `.byn`, gated by the master
// password OR a fresh passkey presence token (parity with BynWrite). Granting
// trust is a proof-of-presence action — an ambient unlocked session is not
// consent. Routes through authorizeTrustGrant (the single trust-authorization
// path shared with handleTrustGrantBulk and handleBynWrite).
func (d *Daemon) handleTrustGrant(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustGrantReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zeroBytes(req.Password)
	if req.Path == "" {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "path required", "")
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	// Authorize via the provider registry; derive the vk-MAC key in one step.
	vkKey, le := d.authorizeTrustGrant(ctx, env.ID, name, st, req.Password, req.PresenceToken)
	if le != nil {
		return le
	}
	defer zeroBytes(vkKey)
	body, _, rerr := readBynFile(req.Path)
	if rerr != nil {
		d.auditEmit(ctx, name, audit.Event{
			Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeBadRequest), BynPath: trust.Canonicalize(req.Path),
		})
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("read %s: %v", req.Path, rerr), "check the path and retry")
	}
	// Mint both MACs (vk from the derived key, fp from the machine key) and
	// record the full v2 record. Parse/ValidateAuth failure → CodeBadRequest.
	canon, hash, changed, policy, gerr := d.putTrustRecordWithKey(ctx, st, name, req.Path, body, vkKey, req.Password)
	if gerr != nil {
		d.auditEmit(ctx, name, audit.Event{
			Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
			ErrorCode: string(ipc.CodeBadRequest), BynPath: trust.Canonicalize(req.Path),
		})
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			fmt.Sprintf("trust refused: %v", gerr),
			"fix the .byn before trusting it")
	}
	// Privsep: best-effort grant the exec service user access to the project
	// dir the .byn lives in (no-op when privsep is off; never fails the grant).
	d.grantProjectACL(req.Path)
	d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK})
	resp, err := ipc.NewResponse(env.ID, ipc.TrustGrantResp{
		Path:            canon,
		SHA256:          hash,
		Changed:         changed,
		Actions:         policy.Actions,
		Auth:            policy.Auth,
		Aliases:         policy.Aliases,
		EnvWildcard:     policy.EnvWildcard,
		ActionsWildcard: policy.ActionsWildcard,
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleTrustGrantBulk trusts many .byn paths against ONE vault, verifying the
// password (or presence token) ONCE and reusing the derived vk-MAC key for
// every path — so trusting N files costs one KDF, not N. Routes through
// authorizeTrustGrant (the single trust-authorization path). A per-file read
// error is reported in that path's result without failing the rest of the batch.
func (d *Daemon) handleTrustGrantBulk(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.TrustGrantBulkReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zeroBytes(req.Password)
	if len(req.Paths) == 0 {
		return ipc.NewError(env.ID, ipc.CodeBadRequest, "no paths to trust", "")
	}
	name := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, name)
	if errEnv != nil {
		return errEnv
	}
	// ONE verification for the whole batch — authorize and derive the vk-MAC
	// key in a single step via the shared authorizeTrustGrant helper.
	vkKey, le := d.authorizeTrustGrant(ctx, env.ID, name, st, req.Password, req.PresenceToken)
	if le != nil {
		return le
	}
	defer zeroBytes(vkKey)

	results := make([]ipc.TrustGrantResult, 0, len(req.Paths))
	for _, p := range req.Paths {
		body, _, rerr := readBynFile(p)
		if rerr != nil {
			d.auditEmit(ctx, name, audit.Event{
				Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
				ErrorCode: string(ipc.CodeBadRequest), BynPath: trust.Canonicalize(p),
			})
			results = append(results, ipc.TrustGrantResult{Path: p, Error: rerr.Error()})
			continue
		}
		canon, hash, changed, policy, perr := d.putTrustRecordWithKey(ctx, st, name, p, body, vkKey, req.Password)
		if perr != nil {
			// Parse/validate failure → per-file error, others continue.
			d.auditEmit(ctx, name, audit.Event{
				Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeDenied,
				ErrorCode: string(ipc.CodeBadRequest), BynPath: trust.Canonicalize(p),
			})
			results = append(results, ipc.TrustGrantResult{Path: p, Error: perr.Error()})
			continue
		}
		// Privsep: best-effort grant the exec service user access to the project
		// dir the .byn lives in (no-op when privsep is off; never fails the grant).
		// Mirrors handleTrustGrant.
		d.grantProjectACL(p)
		d.auditEmit(ctx, name, audit.Event{Op: string(ipc.OpTrustGrant), Outcome: audit.OutcomeOK, BynPath: canon})
		results = append(results, ipc.TrustGrantResult{
			Path:            canon,
			SHA256:          hash,
			Changed:         changed,
			Actions:         policy.Actions,
			Auth:            policy.Auth,
			Aliases:         policy.Aliases,
			EnvWildcard:     policy.EnvWildcard,
			ActionsWildcard: policy.ActionsWildcard,
		})
	}
	out, err := ipc.NewResponse(env.ID, ipc.TrustGrantBulkResp{Results: results})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return out
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
	body, fi, rerr := readBynFile(req.Path)
	if rerr != nil {
		// File gone, unreadable, or oversize: nothing to trust.
		auditExec(trust.Canonicalize(req.Path), string(trust.VerifyUntrusted))
		resp, err := ipc.NewResponse(env.ID, ipc.TrustVerifyResp{
			Path: req.Path, Status: string(trust.VerifyUntrusted),
		})
		if err != nil {
			return internalErr(env.ID, err)
		}
		return resp
	}
	// Use the mtime from the Stat performed inside readBynFile. A nil fi is
	// safe: zero mtime falls back to v1 records ignoring it.
	var currentMTime int64
	if fi != nil {
		currentMTime = fi.ModTime().UnixNano()
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

	status, vkChecked, _, verr := trust.Verify(d.cfg.Dir, canon, hash, currentMTime, d.fpMACKey, vkKey)
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
	// The default project is the base for inheritance and cannot be removed.
	// This check mirrors the default-env protection in vault.DeleteEnv and the
	// default-vault protection in handleVaultDelete — all three must refuse at
	// the daemon layer regardless of lock state or flag setting.
	if req.Name == vault.DefaultProjectName {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"the default project cannot be deleted",
			"create a new project (`byn project create NAME`) or delete a non-default one")
	}
	vaultName := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeAction(ctx, env.ID, vaultName, vault.Scope{Project: req.Name}, st, "delete", req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpProjectDelete),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
		return le
	}
	if err := st.DeleteProject(ctx, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	d.auditEmit(ctx, vaultName, audit.Event{Op: string(ipc.OpProjectDelete), Outcome: audit.OutcomeOK})
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
	// The default project cannot be renamed (it is the inheritance base).
	// Mirror the default-env protection in vault.RenameEnv and the
	// default-vault guard in handleVaultRename — enforced at the daemon layer.
	if req.OldName == vault.DefaultProjectName {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"the default project cannot be renamed",
			"create a new project (`byn project create NAME`) instead")
	}
	vaultName := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeAction(ctx, env.ID, vaultName, vault.Scope{Project: req.OldName}, st, "update", req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpProjectRename),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
		return le
	}
	if err := st.RenameProject(ctx, req.OldName, req.NewName); err != nil {
		return mapVaultErr(env.ID, err)
	}
	d.auditEmit(ctx, vaultName, audit.Event{Op: string(ipc.OpProjectRename), Outcome: audit.OutcomeOK})
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
	vaultName := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	if le := d.authorizeAction(ctx, env.ID, vaultName, vault.Scope{Project: project, Env: req.Name}, st, "delete", req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpEnvDelete),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
		return le
	}
	if err := st.DeleteEnv(ctx, project, req.Name); err != nil {
		return mapVaultErr(env.ID, err)
	}
	d.auditEmit(ctx, vaultName, audit.Event{Op: string(ipc.OpEnvDelete), Outcome: audit.OutcomeOK})
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
	vaultName := defaultIfEmpty(req.Vault, vault.DefaultVaultName)
	project := defaultIfEmpty(req.Project, vault.DefaultProjectName)
	st, errEnv := d.storeForVault(env.ID, req.Vault)
	if errEnv != nil {
		return errEnv
	}
	if le := d.authorizeAction(ctx, env.ID, vaultName, vault.Scope{Project: project, Env: req.OldName}, st, "update", req.Password, req.PresenceToken); le != nil {
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:        string(ipc.OpEnvRename),
			Outcome:   audit.OutcomeDenied,
			ErrorCode: string(le.Err.Code),
		})
		return le
	}
	if err := st.RenameEnv(ctx, project, req.OldName, req.NewName); err != nil {
		return mapVaultErr(env.ID, err)
	}
	d.auditEmit(ctx, vaultName, audit.Event{Op: string(ipc.OpEnvRename), Outcome: audit.OutcomeOK})
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
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "put", errEnv)
		return errEnv
	}

	// Insert stays FREE (additive, leaks nothing — the autonomy matrix);
	// only an OVERWRITE of an existing entry is an "update" needing auth.
	// Try create-only first: success = a free insert in one call.
	// CreateOnly=true checks exact scope (project_id + env_id + name), so
	// a name that exists only in the default env does NOT trigger ErrExists
	// for a non-default env scope — inserting an override stays free.
	//
	// This unconditional flow means the [auth] update="always" policy is
	// enforced even when a session is active — authorizeAction consults the
	// policy first and returns nil when no policy is present and a valid
	// session exists, preserving default session behaviour exactly.
	//
	// NU-3 security: when the vault is locked, the daemon must not reveal vault
	// lock state to unauthenticated callers. Gate inserts behind auth when locked
	// so that an attacker with no session or credentials gets auth_required rather
	// than CodeLocked (which would reveal that the vault is locked).
	if st.IsLocked() {
		vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
		if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "update", req.Password, req.PresenceToken); le != nil {
			d.auditPlane(ctx, req.Scope, "env_var", req.Name, "put", le)
			return le
		}
	}
	var resp *ipc.Envelope
	err := st.PutEnvVar(ctx, scope, req.Name, req.Value, vault.PutOpt{CreateOnly: true})
	if errors.Is(err, vault.ErrExists) && !req.CreateOnly {
		// Row exists in this scope — this is an overwrite, needs auth check.
		vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
		if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "update", req.Password, req.PresenceToken); le != nil {
			d.auditPlane(ctx, req.Scope, "env_var", req.Name, "put", le)
			return le
		}
		err = st.PutEnvVar(ctx, scope, req.Name, req.Value, vault.PutOpt{})
	}
	if err != nil {
		resp = mapVaultErr(env.ID, err)
	} else {
		d.touchVault(req.Scope.Vault)
		out, oerr := ipc.NewResponse(env.ID, ipc.PutResp{})
		if oerr != nil {
			resp = internalErr(env.ID, oerr)
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
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "get", errEnv)
		return errEnv
	}
	if le := d.authorizeAction(ctx, env.ID, defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName), scope, st, "get", req.Password, req.PresenceToken); le != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.Name, "get", le)
		return le
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
	// Populate Empty only when the vault is unlocked. Emptiness is derived
	// from ciphertext length (no decryption, no audit "get" events fire).
	// When locked the field is omitted (nil) — the UI treats nil as "unknown".
	unlocked := !st.IsLocked()
	out := make([]ipc.SecretMeta, 0, len(infos))
	for _, m := range infos {
		meta := ipc.SecretMeta{
			Name:      m.Name,
			Source:    m.Source.String(),
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		}
		if unlocked {
			empty := m.IsEmpty
			meta.Empty = &empty
		}
		out = append(out, meta)
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
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	// authorizeAction: valid session OR fresh credentials (NU-3 matrix).
	// When the vault is locked, authorizeAction authorizes the caller and then
	// st.DeleteEnvVar handles the locked-vault path (returns ErrLocked → CodeLocked
	// when no password is supplied, or decrypts in-place when a password is given).
	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "delete", req.Password, req.PresenceToken); le != nil {
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
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "delete", req.Password, req.PresenceToken); le != nil {
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
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		d.auditPlane(ctx, req.Scope, "env_var", req.OldName, "rename", errEnv)
		return errEnv
	}
	// NU-3: auth gate fires BEFORE the lock check to avoid revealing vault lock
	// state to unauthenticated callers (a locked vault returns auth_required,
	// not CodeLocked, when there is no session or credentials).
	{
		vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
		if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "update", req.Password, req.PresenceToken); le != nil {
			d.auditPlane(ctx, req.Scope, "env_var", req.OldName, "rename", le)
			return le
		}
	}
	// requireUnlocked: rename always needs the vault key (re-encryption under
	// new AAD). After auth passes, check the vault is actually unlocked.
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

// ---- Daemon lifecycle (portal) -----------------------------------------

// handleDaemonReload applies a live config reload and returns the change notes.
// This is the IPC equivalent of sending SIGHUP: no credentials required (parity
// with `byn daemon reload`, which is also ungated).
func (d *Daemon) handleDaemonReload(env *ipc.Envelope) *ipc.Envelope {
	changes, err := d.Reload()
	if err != nil {
		return ipc.NewError(env.ID, ipc.CodeInternal,
			fmt.Sprintf("reload failed: %v", err),
			fmt.Sprintf("check the config file at %s for errors", d.cfg.Dir))
	}
	resp, err := ipc.NewResponse(env.ID, ipc.DaemonReloadResp{ChangeNotes: changes})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleDaemonRestart acknowledges the request and then triggers a graceful
// shutdown asynchronously (~200ms later), giving the HTTP response time to
// reach the browser before the socket is torn down.
//
// Self-respawn is intentionally NOT implemented here: socket handover and
// PID-file coordination across two overlapping daemon processes is hairy and
// risks leaving a zombie if anything goes wrong. Instead the daemon performs a
// clean shutdown and relies on OS auto-start (launchd/systemd) or the user
// running `byn start` to bring it back — the same flow `byn daemon stop` uses.
// The portal is told this in the response message so the user is never surprised.
func (d *Daemon) handleDaemonRestart(env *ipc.Envelope) *ipc.Envelope {
	resp, err := ipc.NewResponse(env.ID, ipc.DaemonRestartResp{
		Message: "daemon stopping — use `byn start` to restart (auto-start relaunches it automatically if installed)",
	})
	if err != nil {
		return internalErr(env.ID, err)
	}
	// Kick off the shutdown in a goroutine so this response reaches the browser
	// before the socket closes. 200ms is enough for a loopback write.
	go func() {
		time.Sleep(200 * time.Millisecond)
		d.Shutdown(5 * time.Second)
	}()
	return resp
}

// handleSessionEnd revokes the session token carried in Envelope.Session. The
// request body is intentionally empty — the token to revoke is in the envelope
// header, threaded into ctx as callerInfo.Session by the dispatch layer (Fix 1).
// Idempotent: ending an already-absent or expired token is a no-op. Audit: the
// caller surface from ctx is stamped on the event; the token value is never logged.
func (d *Daemon) handleSessionEnd(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	// Prefer the token from ctx (Fix 1 seam: callerSession reads callerInfo.Session
	// threaded in by handleConn / Dispatch). Fall back to env.Session for safety.
	tok := callerSession(ctx)
	if len(tok) == 0 {
		tok = env.Session
	}
	// Idempotent even when the envelope carries no session token — the CLI may
	// call this before it has a token (e.g., on a failed unlock attempt).
	if len(tok) > 0 {
		// endToken returns the real vault name so the audit event lands in the
		// correct vault log rather than always blaming "default".
		vaultName, _ := d.sessions.endToken(string(tok))
		if vaultName == "" {
			vaultName = vault.DefaultVaultName // token absent/expired: best-effort
		}
		// Session-end audit: ctx carries the caller surface ("socket" or "portal")
		// stamped by handleConn / Dispatch. Token value is never logged.
		d.auditEmit(ctx, vaultName, audit.Event{
			Op:      string(ipc.OpSessionEnd),
			Outcome: audit.OutcomeOK,
		})
	}
	resp, err := ipc.NewResponse(env.ID, ipc.SessionEndResp{})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleWebBootstrap mints a one-time, 60s-TTL bootstrap token for the portal.
// Only the Unix-socket owner can call this (the socket is mode 0600 + UID-gated
// by peerCred in handleConn). The CLI (`byn web`) calls this op, opens
// ?auth=<token>, and the SPA exchanges it via POST /api/session/bootstrap for
// the persistent portal token — so the long-lived token never appears in ps
// output or URLs.
func (d *Daemon) handleWebBootstrap(env *ipc.Envelope) *ipc.Envelope {
	token, err := d.bootstrapTokens.mint(time.Now())
	if err != nil {
		return internalErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.WebBootstrapResp{Token: token})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleConfigAuth mints a single-use, 60s config-WRITE token. Only the socket
// owner reaches this op (UID-gated by peercred in handleConn). The caller
// (`byn config-auth`) must have already proven sudo via `sudo -v` (PAM) BEFORE
// invoking this — the daemon runs as _byn and cannot run sudo itself, so it
// trusts the owner-UID caller's assertion that sudo passed. That is acceptable
// because the token is single-use + short-TTL: a same-UID attacker could call
// this op, but the code is useless until pasted into one config write, and they
// still could not pass the CLI's `sudo -v` without the OS password.
// (sudo-equivalent, not root-attested — see the design spec, decision B3.)
func (d *Daemon) handleConfigAuth(env *ipc.Envelope) *ipc.Envelope {
	token, err := d.configAuthTokens.mint(time.Now())
	if err != nil {
		return internalErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.ConfigAuthResp{Token: token})
	if err != nil {
		return internalErr(env.ID, err)
	}
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

// authorizeWithPassword verifies the master password against the named vault's
// wrapped key WITHOUT unlocking the vault, regardless of the current lock
// state. Unlike authorizeMutationWhileLocked (which short-circuits when the
// vault is already unlocked), this ALWAYS requires a correct password — used
// for proof-of-presence actions like granting trust, where an ambient unlocked
// session is not consent.
//
// This is a thin wrapper around the "password" auth.Provider in the registry.
// The provider carries the EXACT same rate-limit + audit logic that was
// previously inlined here, preserving zero behavior change.
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.
func (d *Daemon) authorizeWithPassword(ctx context.Context, id, vaultName string, _ *vault.Store, password []byte) *ipc.Envelope {
	p, ok := d.authProviders.Lookup("password")
	if !ok {
		// Should never happen — "password" is registered in New().
		return ipc.NewError(id, ipc.CodeInternal, "password provider not registered", "")
	}
	_, err := p.Verify(ctx, auth.VerifyRequest{
		Vault:    vaultName,
		Action:   "authorize",
		Password: password,
	})
	return mapProviderErr(id, err)
}

// mapProviderErr converts an auth.Provider error into an IPC error envelope
// with the same codes and messages as the pre-registry inline logic.
// nil → nil (authorized). *auth.RetryAfterError is matched directly via
// errors.As to render the "retry after Xs" hint.
//
// Cleanup (a): vault-open failures (ErrNotInit, ErrFingerprintMismatch, etc.)
// wrapped as "auth: open vault: %w" by passwordProvider are unwrapped here so
// they receive their proper codes instead of being misreported as CodeInternal.
//
// Cleanup (b): ErrDenied wording is provider-neutral ("authorization denied")
// rather than passkey-specific. The passkey token path uses its own message
// (CodeBadRequest "passkey authorization expired…") at the call site in
// authorizeTrustGrant/authorizeAction, which is already the correct text for
// that slot. This path is reached when ErrDenied escapes the password
// provider (e.g. an EE "deny" decision), so neutral wording fits.
func mapProviderErr(id string, err error) *ipc.Envelope {
	if err == nil {
		return nil
	}
	var rae *auth.RetryAfterError
	if errors.As(err, &rae) {
		// Rate-limited: reproduce the exact rateLimitCheck envelope.
		return ipc.NewError(id, ipc.CodeRateLimited, rae.Error(),
			fmt.Sprintf("retry after %s", rae.RetryAfter.Round(time.Second)))
	}
	if errors.Is(err, auth.ErrWrongCredential) {
		return ipc.NewError(id, ipc.CodeWrongPassword,
			"could not authorize: wrong password", "verify the password and retry")
	}
	if errors.Is(err, auth.ErrDenied) {
		// Neutral wording: ErrDenied from the password slot means an EE
		// provider explicitly refused — not a passkey expiry.
		return ipc.NewError(id, ipc.CodeAuthRequired,
			"authorization denied",
			"verify your credential and retry")
	}
	// Vault-open errors wrapped by passwordProvider as "auth: open vault: %w".
	// mapVaultErr lacks ErrNotInit/ErrFingerprintMismatch cases (they're only
	// in storeForVault), so map them inline with the same wording and hints.
	if errors.Is(err, vault.ErrNotInit) {
		return ipc.NewError(id, ipc.CodeNotInit,
			"vault is not initialized", "`byn init`")
	}
	if errors.Is(err, vault.ErrFingerprintMismatch) {
		return ipc.NewError(id, ipc.CodeFingerprint,
			vault.ErrFingerprintMismatch.Error(),
			"investigate the wrapped key file before retrying")
	}
	return ipc.NewError(id, ipc.CodeInternal, err.Error(), "")
}

// authorizeAction gates a value-touching op (get / overwrite-put / delete /
// rename / env.clear / structural deletes and renames) according to the NU-3
// authorization matrix.
//
// action is the policy key ("get", "update", "delete"); scope is the
// (project, env) of the operation — used to match the .byn [scope] against
// the trust store. vaultName identifies whose VKMAC key to use.
//
// Policy lookup (policyFor) is attempted only when the vault is unlocked
// (the VKMAC key requires the vault key); a locked vault falls back to
// default matrix semantics. No caching — see policy.go for rationale.
//
// # NU-3 Authorization Matrix (ALWAYS ACTIVE — no flag opt-in)
//
// For value-touching ops (get / overwrite-put / delete / rename / env.clear
// / structural deletes) the gate now operates as follows:
//
//  1. Op governed by a .byn [auth] policy of "always":
//     → fresh provider auth ONLY (password or presence token).
//     A session does NOT satisfy this policy: the .byn demands explicit
//     proof-of-presence, which a session is not.
//
//  2. Policy "none" for this op (trusted .byn context):
//     → free; skip the gate entirely (relaxation for the matched scope).
//
//  3. DEFAULT (no matching policy / vault locked / no .byn in context):
//     → a VALID SESSION for the target vault (validated via
//     callerSession(ctx) + callerInfo UID/TTYDev) OR fresh provider auth
//     (password / presence token).  Neither → CodeAuthRequired.
//     THIS IS ALWAYS ON — the gate is permanently enabled.
//
// Operations that are NEVER satisfied by a session (always require fresh
// credentials): exec.fetch (stays .byn-contract), trust grant,
// config.set, passkey remove, vault delete/passwd — every
// authorizeWithPassword / authorizeActionAlways call site stays fresh.
// Insert (new name) and list stay FREE (not routed through this function).
//
// Deliberate choices NOT routed through this function:
//
//   - vault.rename → routes through authorizeAction ("update"-grade) and IS
//     session-satisfiable. Rationale: a rename is a mutation but recoverable
//     (the vault still exists under a new name). Gating it with fresh
//     credentials every time would be ergonomically expensive for a low-risk
//     operation. The session is proof that the caller already authenticated.
//
//   - trust.remove → completely UNGATED (no auth at all). Rationale: trust
//     removal only REDUCES access — it can never grant anything new. Fail-safe
//     direction: removing trust is a revocation action and must be frictionless
//     so that operators can revoke trust instantly. Gating revocation behind
//     credentials would let friction delay the response to a compromised .byn.
//     Contrast with trust.grant, which is proof-of-presence gated because
//     granting trust is an escalation.
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.
func (d *Daemon) authorizeAction(ctx context.Context, id, vaultName string, scope vault.Scope, st *vault.Store, action string, password, presenceToken []byte) *ipc.Envelope {
	// Step 1: Consult the [auth] policy from any matching, vk-verified trust record.
	if policy, ok := d.policyFor(vaultName, scope); ok {
		switch policy[action] {
		case "always":
			// Policy = always → fresh auth ONLY; session does not satisfy this.
			return d.authorizeActionAlways(ctx, id, vaultName, st,
				"this action requires authorization ([auth] policy = always)",
				"supply the master password to authorize this action",
				password, presenceToken)
		case "none":
			// Policy = none → free for this scope.
			return nil
		}
		// Other values (unknown or absent): fall through to default matrix.
	}

	// Step 2: DEFAULT matrix — valid session OR fresh credentials.
	// A session satisfies the gate; no session requires password/presence token.
	ci := callerFrom(ctx)
	tok := string(callerSession(ctx))
	if tok != "" && d.sessions.validate(tok, vaultName, ci.UID, ci.TTYDev, time.Now()) {
		// Valid session for this vault + caller identity: gate passes.
		return nil
	}
	// No valid session: require fresh credentials (same as authorizeActionAlways
	// but with the session-aware recover hint).
	return d.authorizeActionAlways(ctx, id, vaultName, st,
		"this action requires authorization (run `byn unlock` to start a session, or supply credentials)",
		"run `byn unlock` to start a session, or supply the master password",
		password, presenceToken)
}

// authorizeActionAlways verifies credentials UNCONDITIONALLY — no session is
// accepted. This is the gate used for the [exec] actions contract on
// trusted-.byn exec: the .byn carries its own auth policy that is independent
// of session state. Session state must not silently change the effective policy
// of already-granted .byn files.
//
// authRequiredMsg and recoverHint are returned in CodeAuthRequired when no
// credentials are supplied; callers pass context-specific text.
//
// Token present → routes to "passkey" provider.
// Password present → routes to "password" provider.
// Neither → CodeAuthRequired with the caller-supplied message.
func (d *Daemon) authorizeActionAlways(ctx context.Context, id, vaultName string, st *vault.Store, authRequiredMsg, recoverHint string, password, presenceToken []byte) *ipc.Envelope {
	if len(presenceToken) > 0 {
		// Route through the passkey provider; it burns the token and checks
		// vault binding — same semantics as the former presenceTokens.consume
		// call, wrapped behind the interface.
		p, ok := d.authProviders.Lookup("passkey")
		if !ok {
			return ipc.NewError(id, ipc.CodeInternal, "passkey provider not registered", "")
		}
		_, err := p.Verify(ctx, auth.VerifyRequest{
			Vault:         vaultName,
			Action:        "authorize",
			PresenceToken: presenceToken,
		})
		if err != nil {
			return ipc.NewError(id, ipc.CodeAuthRequired,
				"passkey authorization expired or invalid",
				"re-authenticate with your passkey, or use your password")
		}
		return nil
	}
	if len(password) == 0 {
		return ipc.NewError(id, ipc.CodeAuthRequired, authRequiredMsg, recoverHint)
	}
	return d.authorizeWithPassword(ctx, id, vaultName, st, password)
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
		ipc.CodeAlreadyInit, ipc.CodeBadName, ipc.CodeBadRequest, ipc.CodeEnvProtected,
		ipc.CodeTrustDenied, ipc.CodeAuthRequired:
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
