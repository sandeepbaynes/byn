package daemon

import (
	"context"
	"strings"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// childTmpDir is the writable temp dir handed to a dropped exec child. The
// owner's inherited $TMPDIR is a uid-private dir (e.g. /var/folders/.../T on
// macOS, mode 0700) that the _byn-exec child cannot write — so TMPDIR/TMP/TEMP
// are normalized to a world-writable location the child can always use. Tools
// namespace their own subdirs underneath it (e.g. tsx-451, keyed by uid).
const childTmpDir = "/tmp"

// normalizeChildTmpdir strips inherited TMPDIR/TMP/TEMP entries (which point at
// the owner's uid-private temp dir, unwritable by _byn-exec) and appends ones the
// dropped child can write. Without this, tools that create temp files/sockets
// (tsx, esbuild, node IPC, …) fail with EACCES on the owner's $TMPDIR.
func normalizeChildTmpdir(env []string) []string {
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch k {
		case "TMPDIR", "TMP", "TEMP":
			continue // replaced below with a child-writable dir
		}
		out = append(out, kv)
	}
	out = append(out, "TMPDIR="+childTmpDir, "TMP="+childTmpDir, "TEMP="+childTmpDir)
	return out
}

// isExecHelperUID reports whether uid is a privilege-separation exec-helper
// identity permitted to redeem an exec token: root (the setuid helper before it
// drops) or the _byn-exec service user (after it drops). The owner UID is NEVER
// a helper identity — that is the whole point of token redemption: the owner-UID
// CLI must not be able to fetch the curated secret env.
func (d *Daemon) isExecHelperUID(uid uint32) bool {
	if uid == 0 {
		return true
	}
	return d.execProvisioned.Load() && uid == uint32(d.execUID.Load()) //nolint:gosec // G115: a service-user uid always fits in uint32
}

// execSandboxProfile returns the Seatbelt profile applied to a terminal-anchored
// exec child (darwin: deny byn's own state dir + socket; "" elsewhere). The
// helper applies it AFTER dropping to _byn-exec, so the sandbox confines the
// dropped child rather than the setuid helper.
func (d *Daemon) execSandboxProfile() string {
	return privsep.ExecSandboxProfile(d.cfg.Dir, d.SocketPath(), false)
}

// handleExecAuthorize authorizes a `byn exec` (Option A: Terminal-anchored) and
// mints a one-time token the privsep helper redeems for the curated child
// argv+env. The owner-UID CLI receives ONLY the token — never the secrets.
// Authorization reuses the EXACT gate as exec.fetch/exec.spawn (trust verify,
// [exec] actions, capability/vault values), so a compromised CLI can widen
// nothing. When privsep is not provisioned it returns a clean fallback error so
// the CLI runs the child in-process; it NEVER mints a token it cannot redeem.
func (d *Daemon) handleExecAuthorize(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ExecAuthorizeReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	// Terminal-anchored exec needs the _byn-exec user to redeem + drop. Absent it,
	// fall back cleanly (CLI runs in-process) — never silently widen.
	if !d.execProvisioned.Load() {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"privsep not provisioned (run `byn setup`)", "byn setup")
	}

	// Shared authorization gate — identical to exec.fetch/exec.spawn. It audits the
	// authorization decision exactly once (denials already audited); we must not
	// re-audit on success here.
	values, resolvedArgv, wildcard, noneDeclared, actionsWildcard, le := d.authorizeExec(ctx, env.ID, req.ExecFetchReq)
	if le != nil {
		return le
	}

	// Validate the CLI-resolved absolute target against the authorized command
	// (its basename must match resolvedArgv[0] — see validateAbsTarget).
	if le := d.validateAbsTarget(env.ID, req.AbsTarget, resolvedArgv); le != nil {
		d.auditSpawnFailure(ctx, req.ExecFetchReq, le)
		return le
	}

	// Build the COMPLETE child env: base env (dangerous dynamic-linker keys
	// stripped — the daemon never trusts BaseEnv verbatim) first, injected secrets
	// last so they win on duplicate keys. Zero the secret value buffers afterward
	// (best-effort; they now live as strings inside childEnv, exactly as in
	// exec.spawn, until the token is redeemed or swept).
	baseEnv := stripDangerousEnv(req.BaseEnv)
	childEnv := make([]string, 0, len(baseEnv)+len(values))
	childEnv = append(childEnv, baseEnv...)
	childEnv = append(childEnv, valuesToEnv(values)...)
	for _, v := range values {
		zeroBytes(v.Value)
	}
	// The owner's $TMPDIR is uid-private (0700) and unwritable by _byn-exec —
	// redirect the child's temp to a writable location.
	childEnv = normalizeChildTmpdir(childEnv)

	// Spawn argv: the validated absolute target + the authorized args.
	spawnArgv := append([]string{req.AbsTarget}, resolvedArgv[1:]...)

	tok, mErr := d.execTokens.mint(spawnArgv, childEnv, d.execSandboxProfile())
	if mErr != nil {
		return internalErr(env.ID, mErr)
	}
	resp, rerr := ipc.NewResponse(env.ID, ipc.ExecAuthorizeResp{
		Token:           tok,
		Wildcard:        wildcard,
		NoneDeclared:    noneDeclared,
		ActionsWildcard: actionsWildcard,
	})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// handleExecRedeem exchanges a one-time token for the daemon-authorized child
// argv + curated env + sandbox profile. It is RESTRICTED to the privsep helper
// (peercred root or _byn-exec) — the owner-UID CLI is rejected so the curated
// secrets never enter owner-UID memory. There is no trust/auth logic here:
// authorization happened at exec.authorize; the one-time token IS the capability.
func (d *Daemon) handleExecRedeem(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	if !d.isExecHelperUID(callerFrom(ctx).UID) {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"exec.redeem is restricted to the privsep exec helper", "")
	}
	var req ipc.ExecRedeemReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zeroBytes(req.Token)
	argv, cenv, profile, ok := d.execTokens.redeem(req.Token)
	if !ok {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"invalid or expired exec token", "")
	}
	resp, rerr := ipc.NewResponse(env.ID, ipc.ExecRedeemResp{
		Argv: argv, Env: cenv, SandboxProfile: profile,
	})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}
