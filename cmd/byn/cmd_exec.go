package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runExec loads env-var entries from the vault and replaces the
// current process with the named command, passing those entries plus
// the existing environment to the child.
//
// Why syscall.Exec instead of os/exec.Cmd.Run:
//
//   - replace-in-place leaves no parent byn process to shepherd
//     the child. The child becomes the same PID as the byn CLI
//     that invoked it. Signal handling is automatic — signals go
//     directly to the child.
//   - cleaner ps tree: an agent invoked via `byn exec` looks like
//     a top-level process, not a byn sub-process.
//   - the values we just decrypted live in our heap only between
//     the exec.fetch response and the exec syscall. After exec, our
//     process image is replaced and the strings are gone with it.
//     (Best-effort hygiene; values do briefly exist as Go strings
//     in our heap.)
//
// exec.fetch returns the full injection set in one round-trip: the
// daemon trust-verifies the .byn, applies the [exec] env allowlist
// server-side, and returns only approved name/value pairs.
//
// Two grammars:
//
//	byn exec -- COMMAND [ARGS...]    (direct form)
//	byn exec NAME [ARGS...]          (alias form)
//
// In the direct form, "--" is required so COMMAND's own flags are not
// misinterpreted by the exec flag parser. In the alias form, the first
// token after "exec" (not "--" and not a flag) is the alias name; the
// daemon expands it from the trusted .byn's [aliases] table.
//
// Alias shadowing: `byn exec test` with alias "test" defined runs the
// alias; `byn exec -- test` runs the literal binary "test".
//
// Limitations of v1 (intentional, to be iterated on):
//
//   - injected values briefly exist as Go strings in heap between
//     exec.fetch and syscall.Exec. Mitigatable later with secmem +
//     a direct execve wrapper; not worth the cgo for v1.
//   - shell builtins (cd, source, etc.) cannot be exec'd directly —
//     wrap them via `bash -c '...'`.
func runExec(args []string, scope cliScope) int {
	// Strip the byn-exec `--no-privsep` flag BEFORE the alias/direct dispatch.
	// It is byn's own flag (like the global scope flags the pre-parser handles),
	// so it must appear before the `--` separator in direct form and before the
	// alias NAME in alias form. Anything after `--` (or after the alias name) is
	// the child's argv and is never scanned for it. When set, it forces the
	// legacy in-process path regardless of [security] privsep.
	args, noPrivsep := stripNoPrivsep(args)

	// Dispatch: alias form vs direct form.
	// Alias form: first arg is non-empty, does not start with "-", and is not "--".
	// Direct form: first arg is "--" (or we get the usage error below).
	var (
		aliasName   string   // non-empty only for alias form
		extraArgs   []string // alias passthrough args (alias form) or full argv (direct)
		childArgv   []string // the argv we locally track for LookPath/fallback
		isAliasExec bool
	)

	if len(args) > 0 && args[0] != "--" && !strings.HasPrefix(args[0], "-") {
		// Alias form: NAME [ARGS...]
		if scope.SourcePath == "" {
			fmt.Fprintln(os.Stderr, boldRed("Error:")+" no .byn in scope — aliases are defined in a trusted .byn ([aliases])")
			fmt.Fprintln(os.Stderr, dim("Hint: run from a directory with a trusted .byn, or use `byn exec -- COMMAND` for direct exec"))
			return exitErr
		}
		aliasName = args[0]
		extraArgs = args[1:]
		isAliasExec = true
		// childArgv is not known until the daemon responds with ResolvedArgv.
		// We use a placeholder; it will be replaced by ResolvedArgv below.
		childArgv = nil
	} else {
		// Direct form: find the "--" separator.
		sepIdx := -1
		for i, a := range args {
			if a == "--" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 0 {
			fmt.Fprintln(os.Stderr, "Usage: byn exec -- COMMAND [ARGS...]")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, dim("The `--` separator is required to disambiguate exec's own flags"))
			fmt.Fprintln(os.Stderr, dim("from the child command's flags. See `byn exec help` for examples."))
			fmt.Fprintln(os.Stderr, dim("To run an alias defined in the .byn, use: byn exec NAME [ARGS...]"))
			return exitErr
		}
		childArgv = args[sepIdx+1:]
		if len(childArgv) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: byn exec -- COMMAND [ARGS...]")
			return exitErr
		}
		extraArgs = childArgv
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	client := newClient(dir, "")

	// The CLI is a separate process from the daemon, so it learns whether
	// privsep is enabled by reading the SAME ~/.byn/config the daemon reads
	// (config.Load on the data dir). A missing/invalid file yields defaults
	// (privsep OFF) — we never want a config read error to block exec, so a
	// load failure degrades to the legacy in-process path silently.
	privsepOn := !noPrivsep
	if privsepOn {
		cfg, cerr := config.Load(config.Path(dir))
		privsepOn = cerr == nil && cfg.PrivsepEnabled()
	}

	// One round-trip: the daemon verifies trust, enforces the .byn's
	// [exec] env allowlist AND [exec] actions pinlist server-side, and
	// returns only approved values (a compromised CLI can't widen either
	// list — NU-1 + NU-2).
	//
	// Auth-retry cases (prompt once, then retry with password):
	//   1. Ad-hoc exec (no .byn) when no session is present.
	//   2. Trusted-.byn exec when the command is NOT pinned in [exec] actions
	//      (the daemon returns auth_required with the "not pinned" message).
	// Both cases prompt on TTY; on non-TTY they fail with an actionable hint.
	// For direct exec: Argv is sent untruncated for actions matching;
	// Command is the ≤200-char audit label.
	// For alias exec: Alias holds the name; Argv holds the extra args only.
	var req ipc.ExecFetchReq
	if isAliasExec {
		req = ipc.ExecFetchReq{
			Path:    scope.SourcePath,
			Scope:   scope.ToIPC(),
			Command: "alias " + aliasName, // label overridden by daemon to resolved form
			Alias:   aliasName,
			Argv:    extraArgs,
		}
	} else {
		cmd := execCommandLabel(childArgv)
		req = ipc.ExecFetchReq{
			Path:    scope.SourcePath,
			Scope:   scope.ToIPC(),
			Command: cmd,
			Argv:    childArgv,
		}
	}

	// PRIVSEP ROUTING (NU-5). When [security] privsep is enabled and this is a
	// trusted-.byn DIRECT exec, the daemon spawns the child SERVER-side under the
	// _byn-exec service user (so other same-UID processes can't read the injected
	// secrets from the child's environment). The child's stdio fds travel to the
	// daemon out-of-band via SCM_RIGHTS; the child's exit code comes back in the
	// response.
	//
	// Scope of the privsep path (everything else uses the legacy in-process path):
	//   - ad-hoc exec (scope.SourcePath == "") → LEGACY. privsep confines only the
	//     trusted-.byn pinned exec contract; ad-hoc runs in-process (resolves the
	//     T6 ad-hoc gap — ad-hoc has no .byn to bind the spawn to).
	//   - alias exec → LEGACY. The CLI cannot resolve AbsTarget up front because
	//     the alias is expanded SERVER-side (childArgv[0] is unknown until the
	//     daemon returns ResolvedArgv). Direct exec only for v1.
	//   - --no-privsep, or privsep off (the DEFAULT) → LEGACY, byte-for-byte.
	if privsepOn && scope.SourcePath != "" && !isAliasExec {
		if rc, handled := runExecPrivsep(client, req, childArgv); handled {
			return rc
		}
		// Not handled ⇒ the daemon predates exec.spawn (unknown_op). Fall through
		// to the legacy in-process path below.
	}

	var fetched ipc.ExecFetchResp
	callErr := client.Call(ipc.OpExecFetch, req, &fetched)
	switch {
	case callErr == nil:
		// success — fall through
	case isAuthRequiredErr(callErr):
		// Auth_required fires for two cases:
		//   (a) ad-hoc exec (Path == "") with no session present
		//   (b) trusted-.byn exec with an unmatched/empty [exec] actions
		// Both take the same retry path. The daemon's message distinguishes
		// them for the user; we just need to get the password and retry.
		if !stdinIsTTY() {
			// Non-TTY path: fail with an actionable hint.
			// Extract the daemon message if available for a richer hint.
			var em *ipc.ErrResponse
			if errors.As(callErr, &em) {
				fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red(em.Message+"."))
				if scope.SourcePath != "" {
					// Trusted-.byn unmatched: hint about adding to [exec] actions.
					fmt.Fprintf(os.Stderr, "%s %s\n",
						dim("Hint:"), dim("add the command to [exec] actions in "+scope.SourcePath+" and re-trust, or run interactively to supply the password"))
				} else {
					// Ad-hoc: hint about .byn.
					fmt.Fprintf(os.Stderr, "%s %s\n",
						dim("Hint:"), dim("run from a directory with a trusted .byn (credential-free), or unlock the vault's UI portal"))
				}
			} else {
				fmt.Fprintf(os.Stderr, "%s exec requires authorization.\n", boldRed("Error:"))
				fmt.Fprintf(os.Stderr, "%s %s\n",
					dim("Hint:"), dim("run from a directory with a trusted .byn (credential-free), or supply the password interactively"))
			}
			return exitDaemonErr
		}
		// Interactive TTY path: prompt once and retry.
		var leadIn string
		if scope.SourcePath != "" {
			// Trusted .byn, but command not pinned in [exec] actions.
			var em *ipc.ErrResponse
			if errors.As(callErr, &em) {
				leadIn = yellow("Authorization required.") + dim(" "+em.Message+".")
			} else {
				leadIn = yellow("Authorization required.") + dim(" Command not pinned in [exec] actions.")
			}
		} else {
			leadIn = yellow("Authorization required.") + dim(" Enter the master password to authorize.")
		}
		pw, wipe, perr := authorizingPasswordWithLeadIn(false, leadIn)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
			return exitErr
		}
		defer wipe()
		req.Password = pw
		if retryErr := client.Call(ipc.OpExecFetch, req, &fetched); retryErr != nil {
			return handleExecFetchError(retryErr)
		}
	case isAliasExec:
		// Alias-specific error rendering.
		var em *ipc.ErrResponse
		if errors.As(callErr, &em) && em.Code == ipc.CodeNotFound {
			fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), em.Message)
			return exitDaemonErr
		}
		return handleExecFetchError(callErr)
	default:
		return handleExecFetchError(callErr)
	}
	renderAllowlistNotes(fetched, scope.SourcePath)

	// Use the daemon's ResolvedArgv as the authoritative argv. For direct exec
	// this matches childArgv. For alias exec this is the expanded form. The CLI
	// always prefers ResolvedArgv — single contract from the daemon.
	if len(fetched.ResolvedArgv) > 0 {
		childArgv = fetched.ResolvedArgv
	} else if isAliasExec {
		// Should not happen on a well-behaved daemon; fail fast.
		fmt.Fprintln(os.Stderr, boldRed("Error:")+" daemon did not return ResolvedArgv for alias exec")
		return exitErr
	}
	// childArgv is already set for direct exec (and confirmed via ResolvedArgv when available).

	extraEnv := make([]string, 0, len(fetched.Values))
	for _, v := range fetched.Values {
		extraEnv = append(extraEnv, v.Name+"="+string(v.Value))
		zero(v.Value)
	}

	// Resolve the binary in PATH. We do this BEFORE the env merge so a
	// missing binary fails fast with a clear message, without ever
	// materializing the env vars in a syscall.
	cmdPath, err := exec.LookPath(childArgv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	// Build the env. Parent's environ first so injected vars can shadow it
	// (last value wins per POSIX, and most shells/libs follow that). This
	// means a stored DB_URL overrides any DB_URL already exported in the
	// parent shell — usually what the user wants.
	envv := append(os.Environ(), extraEnv...)

	// Replace the process. On success, this never returns.
	// gosec G204 flags subprocess launches with variable paths;
	// suppressed because variable path IS the operation here —
	// the user explicitly named the command, and we resolved it
	// via exec.LookPath which already vets PATH membership.
	if err := syscall.Exec(cmdPath, childArgv, envv); err != nil { //nolint:gosec
		fmt.Fprintf(os.Stderr, "%s exec: %v\n", boldRed("Error:"), err)
		return exitErr
	}
	// Unreachable if Exec succeeded.
	return exitErr
}

// stripNoPrivsep removes the byn-exec `--no-privsep` flag from the part of args
// that belongs to byn (everything up to the first `--` separator or the first
// non-flag alias-NAME token). Tokens at/after that boundary are the child's argv
// and are passed through opaquely — a child of its own may legitimately take a
// `--no-privsep` flag. Returns the cleaned args and whether the flag was present.
func stripNoPrivsep(args []string) ([]string, bool) {
	out := make([]string, 0, len(args))
	found := false
	boundary := false // once true, copy the rest verbatim (child argv)
	for _, a := range args {
		if boundary {
			out = append(out, a)
			continue
		}
		if a == "--" {
			// Direct-form separator: byn flags end here.
			boundary = true
			out = append(out, a)
			continue
		}
		if !strings.HasPrefix(a, "-") {
			// Alias NAME (or a bare token): byn flag parsing ends here too.
			boundary = true
			out = append(out, a)
			continue
		}
		if a == "--no-privsep" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// runExecPrivsep drives the SERVER-side privsep spawn for a trusted-.byn DIRECT
// exec. It resolves the child binary, builds the ExecSpawnReq (the SAME
// ExecFetchReq the legacy path would send, PLUS BaseEnv + the resolved
// AbsTarget), and calls CallWithFDs passing the child's three stdio fds via
// SCM_RIGHTS. The daemon authorizes (shared gate with exec.fetch), drops the
// child to _byn-exec, and returns its exit code.
//
// handled=false means the daemon does not know exec.spawn (unknown_op) — an
// older daemon — and the caller should fall back to the legacy in-process path.
// In every other case handled=true and rc is the final exit code.
//
// Auth retry mirrors the legacy path: on a TTY, an auth_required reply prompts
// once for the master password and retries. A not-provisioned reply (privsep
// enabled but `byn setup` never run) is a HARD error with an actionable hint —
// we never silently fall back to an owner-UID in-process run, because the user
// explicitly opted into privsep.
func runExecPrivsep(client *ipc.Client, req ipc.ExecFetchReq, childArgv []string) (rc int, handled bool) {
	// Resolve the child binary in PATH. Same failure mode as the legacy path.
	absTarget, err := exec.LookPath(childArgv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr, true
	}

	spawnReq := ipc.ExecSpawnReq{
		ExecFetchReq: req,
		BaseEnv:      os.Environ(),
		AbsTarget:    absTarget,
	}
	stdio := []int{int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd())}

	var resp ipc.ExecSpawnResp
	callErr := client.CallWithFDs(ipc.OpExecSpawn, spawnReq, &resp, client.Session, stdio)

	// Auth retry: an auth_required reply on a TTY prompts once and retries with
	// the password attached. Same UX as the legacy exec.fetch path.
	if isAuthRequiredErr(callErr) && stdinIsTTY() {
		leadIn := yellow("Authorization required.") + dim(" Enter the master password to authorize.")
		if scopeHasByn(req) {
			var em *ipc.ErrResponse
			if errors.As(callErr, &em) {
				leadIn = yellow("Authorization required.") + dim(" "+em.Message+".")
			} else {
				leadIn = yellow("Authorization required.") + dim(" Command not pinned in [exec] actions.")
			}
		}
		pw, wipe, perr := authorizingPasswordWithLeadIn(false, leadIn)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
			return exitErr, true
		}
		defer wipe()
		spawnReq.Password = pw
		callErr = client.CallWithFDs(ipc.OpExecSpawn, spawnReq, &resp, client.Session, stdio)
	}

	switch {
	case callErr == nil:
		// The child ran SERVER-side and exited; propagate its exit code as our
		// own. We return it (rather than os.Exit) so run()/main does the exit —
		// keeps runExec testable and matches every other command handler.
		return resp.ExitCode, true
	case isNotProvisionedErr(callErr):
		// Privsep was explicitly requested but `byn setup` never provisioned the
		// service users. This is actionable and must NOT silently fall back to an
		// owner-UID in-process run — that would defeat the opt-in.
		fmt.Fprintln(os.Stderr, boldRed("Error:")+" privsep is enabled but not set up.")
		fmt.Fprintln(os.Stderr, yellow("Run:")+" "+cyan("sudo byn setup")+"   "+
			dim("(or disable [security] privsep, or pass --no-privsep)"))
		return exitDaemonErr, true
	case isUnknownOpErr(callErr):
		// Daemon predates exec.spawn — signal the caller to use the legacy path.
		return 0, false
	default:
		return handleExecFetchError(callErr), true
	}
}

// scopeHasByn reports whether the exec request is bound to a trusted .byn (so
// an auth_required reply means "command not pinned" rather than "ad-hoc gated").
func scopeHasByn(req ipc.ExecFetchReq) bool { return req.Path != "" }

// isNotProvisionedErr reports whether err is the daemon's "privsep not
// provisioned" reply — a CodeBadRequest whose recover hint is `byn setup`. The
// daemon returns this when [security] privsep is on but `byn setup` has not run.
func isNotProvisionedErr(err error) bool {
	var em *ipc.ErrResponse
	return errors.As(err, &em) && em.Code == ipc.CodeBadRequest && em.Recover == "byn setup"
}

// isUnknownOpErr reports whether err is the daemon's unknown_op reply (the
// daemon is older than this CLI and does not implement the requested op).
func isUnknownOpErr(err error) bool {
	var em *ipc.ErrResponse
	return errors.As(err, &em) && em.Code == ipc.CodeUnknownOp
}

// execCommandLabel renders the child argv for the audit log (so a
// .byn-authorized injection is traceable to the command it ran), capped to keep
// audit lines bounded.
func execCommandLabel(argv []string) string {
	s := strings.Join(argv, " ")
	const maxLen = 200
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// handleExecFetchError renders exec.fetch failures. Trust denials carry
// the daemon's reason + the recovery command; an unknown_op means the
// daemon predates exec.fetch; auth_required means the ad-hoc exec is
// gated and no credentials were supplied (or the retry path reached here
// with a wrong-password error).
func handleExecFetchError(err error) int {
	var em *ipc.ErrResponse
	if errors.As(err, &em) {
		switch em.Code {
		case ipc.CodeTrustDenied:
			fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red(em.Message+"."))
			if em.Recover != "" {
				hint := ""
				if strings.HasPrefix(em.Recover, "byn trust") {
					hint = " " + dim("(byn asks for the master password)")
				}
				fmt.Fprintf(os.Stderr, "%s %s%s\n", yellow("Run:"), cyan(em.Recover), hint)
			}
			return exitDaemonErr
		case ipc.CodeAuthRequired:
			fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red(em.Message+"."))
			fmt.Fprintf(os.Stderr, "%s %s\n",
				dim("Hint:"), dim("run from a directory with a trusted .byn (credential-free), or supply the master password"))
			return exitDaemonErr
		case ipc.CodeUnknownOp:
			fmt.Fprintf(os.Stderr, "%s daemon is older than this CLI.\n", boldRed("Error:"))
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Run:"), cyan("byn restart"))
			return exitErr
		}
	}
	return handleCallError(err)
}

// renderAllowlistNotes prints the wildcard warning / empty-allowlist note
// the daemon's flags request (messages match the pre-NU client-side text).
// Also prints the [exec] actions wildcard warning when ActionsWildcard=true.
func renderAllowlistNotes(resp ipc.ExecFetchResp, sourcePath string) {
	if sourcePath == "" {
		return
	}
	if resp.Wildcard {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("Warning:"),
			yellow(fmt.Sprintf("%s permits ALL %d scoped var(s) via \"*\" — any secret added later is auto-injected.",
				sourcePath, len(resp.Values))))
	} else if resp.NoneDeclared {
		fmt.Fprintf(os.Stderr, "%s\n",
			dim(fmt.Sprintf("note: %s declares no [exec] env vars — injecting none.", sourcePath)))
	}
	if resp.ActionsWildcard {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldYellow("Warning:"),
			yellow(fmt.Sprintf("%s pins NO specific actions — \"*\" lets ANY command run re-auth-free.", sourcePath)))
	}
}
