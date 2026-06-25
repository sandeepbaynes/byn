package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ---- stdio-fd context seam (Task 6) ----------------------------------------
//
// The 3 stdio fds for an exec.spawn child arrive out-of-band via SCM_RIGHTS on
// the connection. Task 8 wires the daemon's handleConn to RecvFDs and stashes
// them in the per-request context via withExecSpawnFDs. handleExecSpawn reads
// them back via execSpawnFDs. Keeping this as a context seam lets the tests
// drive handleExecSpawn directly with a ctx pointing at test pipes, before the
// full SCM_RIGHTS transport lands.

type ctxKeyExecSpawnFDs struct{}

// execSpawnFDsValue carries the three raw stdio fd numbers through the request
// context. ok is implied by the value's presence in the context.
type execSpawnFDsValue struct {
	stdin, stdout, stderr int
}

// withExecSpawnFDs returns a ctx carrying the three stdio fd numbers the
// exec.spawn child should use. Task 8 calls this from handleConn after RecvFDs;
// tests call it directly with pipe fds.
func withExecSpawnFDs(ctx context.Context, stdin, stdout, stderr int) context.Context {
	return context.WithValue(ctx, ctxKeyExecSpawnFDs{}, execSpawnFDsValue{
		stdin: stdin, stdout: stdout, stderr: stderr,
	})
}

// execSpawnFDs returns the three stdio fd numbers stashed in ctx and ok=true,
// or (0,0,0,false) when no fds were passed (older client / no SCM_RIGHTS).
func execSpawnFDs(ctx context.Context) (stdin, stdout, stderr int, ok bool) {
	v, ok := ctx.Value(ctxKeyExecSpawnFDs{}).(execSpawnFDsValue)
	if !ok {
		return 0, 0, 0, false
	}
	return v.stdin, v.stdout, v.stderr, true
}

// ---- exec.spawn handler ----------------------------------------------------

// valuesToEnv turns each injected ExecFetchValue into a "NAME=value" string for
// the child environment.
func valuesToEnv(values []ipc.ExecFetchValue) []string {
	env := make([]string, 0, len(values))
	for _, v := range values {
		env = append(env, v.Name+"="+string(v.Value))
	}
	return env
}

// dangerousEnvKeys are dynamic-linker controls that can make a freshly-spawned
// child load attacker-supplied code (LD_PRELOAD / LD_AUDIT, the macOS DYLD_*
// equivalents, and the library-search overrides). The daemon receives BaseEnv
// from the (potentially compromised) CLI, so it must NOT trust it verbatim:
// these keys are stripped at the boundary before the child env is built. The
// child still inherits the rest of the terminal env; injected secrets are
// appended afterward and are unaffected.
var dangerousEnvKeys = map[string]struct{}{
	"LD_PRELOAD":            {},
	"LD_LIBRARY_PATH":       {},
	"LD_AUDIT":              {},
	"DYLD_INSERT_LIBRARIES": {},
	"DYLD_LIBRARY_PATH":     {},
	"DYLD_FRAMEWORK_PATH":   {},
}

// stripDangerousEnv returns env with every entry whose KEY is in
// dangerousEnvKeys removed. Entries without an '=' are kept as-is (a malformed
// pair is not a dynamic-linker control). The input slice is not mutated.
func stripDangerousEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		eq := -1
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				eq = i
				break
			}
		}
		if eq >= 0 {
			if _, bad := dangerousEnvKeys[kv[:eq]]; bad {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}

// handleExecSpawn runs a `byn exec` child SERVER-side under privilege separation
// (NU-5). It reuses handleExecFetch's authorization via the shared authorizeExec
// gate, then spawns the resolved target through the privsep helper, which drops
// the child to the _byn-exec service user. The daemon itself stays at the owner
// UID; it NEVER spawns the child at the owner UID from here.
//
// Security:
//   - When privsep is not provisioned (d.spawner == nil) the op returns a clean
//     bad-request error so the CLI can fall back to client-side exec (Task 8
//     decides per config). The daemon never spawns owner-UID as a fallback.
//   - The child env is BaseEnv (the owner terminal env the CLI sent) followed by
//     the injected secret values, so injected values WIN on duplicate keys.
//   - AbsTarget is validated: non-empty, absolute, a regular file, AND its
//     basename must match the basename of the .byn-authorized command's first
//     token (resolvedArgv[0]). This stops a caller from authorizing "aws" but
//     redirecting exec to "/evil/malware". Full same-UID rogue protection is
//     NU-6.
func (d *Daemon) handleExecSpawn(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.ExecSpawnReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}

	// Privsep must be provisioned. When it is not, do NOT spawn owner-UID —
	// return a clean fallback error so the CLI can run the child client-side.
	if d.spawner == nil {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"privsep not provisioned (run `byn setup`)", "byn setup")
	}

	// The child's stdio fds must have been passed via SCM_RIGHTS (Task 8). An
	// older client that does not pass fds cannot use exec.spawn.
	inFd, outFd, errFd, ok := execSpawnFDs(ctx)
	if !ok {
		return ipc.NewError(env.ID, ipc.CodeBadRequest,
			"exec.spawn requires stdio fds (older client without fd passing?)", "")
	}

	// Shared authorization gate — identical to exec.fetch (already audited on
	// denial; the success path audits the authorization exactly once).
	values, resolvedArgv, _, _, _, le := d.authorizeExec(ctx, env.ID, req.ExecFetchReq)
	if le != nil {
		return le
	}

	// Build the COMPLETE child env: BaseEnv first (with dangerous dynamic-linker
	// keys stripped — defense in depth: the daemon must not trust BaseEnv
	// verbatim), injected values last so the injected secrets win on duplicate
	// keys. Stripping happens BEFORE the append so a caller cannot smuggle an
	// LD_PRELOAD that loads attacker code into the dropped child.
	baseEnv := stripDangerousEnv(req.BaseEnv)
	childEnv := make([]string, 0, len(baseEnv)+len(values))
	childEnv = append(childEnv, baseEnv...)
	childEnv = append(childEnv, valuesToEnv(values)...)

	// Validate the CLI-resolved absolute target (SECURITY).
	if le := d.validateAbsTarget(env.ID, req.AbsTarget, resolvedArgv); le != nil {
		// Audit the post-auth spawn failure (the auth itself succeeded above).
		d.auditSpawnFailure(ctx, req.ExecFetchReq, le)
		return le
	}

	// Build the spawn argv: the validated absolute target + the authorized args.
	spawnArgv := append([]string{req.AbsTarget}, resolvedArgv[1:]...)

	code, serr := d.spawner.Spawn(privsep.SpawnReq{
		Argv:   spawnArgv,
		Env:    childEnv,
		Stdin:  inFd,
		Stdout: outFd,
		Stderr: errFd,
	})
	if serr != nil {
		// ErrNotProvisioned / ErrUnsupported → clean fallback (CLI runs locally).
		if errors.Is(serr, privsep.ErrNotProvisioned) || errors.Is(serr, privsep.ErrUnsupported) {
			le := ipc.NewError(env.ID, ipc.CodeBadRequest,
				"privsep not provisioned (run `byn setup`)", "byn setup")
			d.auditSpawnFailure(ctx, req.ExecFetchReq, le)
			return le
		}
		ie := internalErr(env.ID, serr)
		d.auditSpawnFailure(ctx, req.ExecFetchReq, ie)
		return ie
	}

	// Clean spawn. The authorization was already audited "ok" by authorizeExec;
	// do NOT double-audit the success here. The child's exit code is the child's
	// own status, not an IPC error.
	resp, rerr := ipc.NewResponse(env.ID, ipc.ExecSpawnResp{ExitCode: code})
	if rerr != nil {
		return internalErr(env.ID, rerr)
	}
	return resp
}

// validateAbsTarget enforces that AbsTarget is non-empty, absolute, a regular
// file, and bound to the authorized command: its basename must equal the
// basename of resolvedArgv[0] (the .byn-authorized command's first token). This
// prevents a caller from authorizing one command and redirecting exec to an
// unrelated binary. Returns a CodeBadRequest envelope on any failure, else nil.
func (d *Daemon) validateAbsTarget(id, absTarget string, resolvedArgv []string) *ipc.Envelope {
	if absTarget == "" {
		return ipc.NewError(id, ipc.CodeBadRequest,
			"exec.spawn requires a resolved absolute target", "")
	}
	if !filepath.IsAbs(absTarget) {
		return ipc.NewError(id, ipc.CodeBadRequest,
			"resolved target must be an absolute path", "")
	}
	fi, err := os.Stat(absTarget)
	if err != nil {
		// Most common cause: the daemon (_byn) cannot traverse the path to the
		// target binary — e.g. ~/.local/bin/ has no ACL for _byn. The error
		// message includes the OS reason so the user can diagnose it.
		return ipc.NewError(id, ipc.CodeBadRequest,
			fmt.Sprintf("exec target not accessible: %v — run `byn trust .` to refresh ACLs, or check that the tool is in a world-traversable path", err), "")
	}
	if !fi.Mode().IsRegular() {
		// Symlinks are followed by os.Stat, so this catches directories, named
		// pipes, and dangling symlinks resolved to a non-file. Shebang scripts
		// ARE regular files and pass this check; if one fails it is the stat
		// above (daemon can't read the path), not this branch.
		return ipc.NewError(id, ipc.CodeBadRequest,
			fmt.Sprintf("exec target %q is not a regular file (type: %s); if this is a script, invoke it via its interpreter: e.g. `python3 script.py` instead of `./script.py`", filepath.Base(absTarget), fi.Mode().Type()), "")
	}
	if len(resolvedArgv) == 0 {
		return ipc.NewError(id, ipc.CodeBadRequest,
			"no authorized command to bind the resolved target to", "")
	}
	if filepath.Base(absTarget) != filepath.Base(resolvedArgv[0]) {
		return ipc.NewError(id, ipc.CodeBadRequest,
			"resolved target does not match the authorized command", "")
	}
	return nil
}

// auditSpawnFailure emits a single "exec" audit event for a spawn-level failure
// that happens AFTER a clean authorization (which authorizeExec already audited
// "ok"). This records the failed spawn outcome without double-counting the
// authorization. Audit only fires for post-auth spawn errors — never for a
// successful spawn (that would double-log "exec ok").
func (d *Daemon) auditSpawnFailure(ctx context.Context, req ipc.ExecFetchReq, resp *ipc.Envelope) {
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)
	canon := ""
	if req.Path != "" {
		canon = trust.Canonicalize(req.Path)
	}
	outcome, code := outcomeFor(resp)
	d.auditEmit(ctx, vaultName, audit.Event{
		Op: "exec", Outcome: outcome, BynPath: canon,
		Command: req.Command, ErrorCode: code,
	})
}
