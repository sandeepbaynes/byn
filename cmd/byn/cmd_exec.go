package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

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
// Limitations of v1 (intentional, to be iterated on):
//
//   - injected values briefly exist as Go strings in heap between
//     exec.fetch and syscall.Exec. Mitigatable later with secmem +
//     a direct execve wrapper; not worth the cgo for v1.
//   - shell builtins (cd, source, etc.) cannot be exec'd directly —
//     wrap them via `bash -c '...'`.
func runExec(args []string, scope cliScope) int {
	// Find the "--" separator. Everything after it is the child argv.
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
		return exitErr
	}
	childArgv := args[sepIdx+1:]
	if len(childArgv) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: byn exec -- COMMAND [ARGS...]")
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	client := newClient(dir)

	// One round-trip: the daemon verifies trust, enforces the .byn's
	// [exec] env allowlist server-side, and returns only approved values
	// (a compromised CLI can't widen the list — NU-1).
	//
	// Ad-hoc exec (no .byn) is gated under [security] per_action_auth:
	// if the first call returns auth_required, prompt once and retry with
	// the password. Trusted-.byn exec is always credential-free.
	cmd := execCommandLabel(childArgv)
	req := ipc.ExecFetchReq{
		Path:    scope.SourcePath,
		Scope:   scope.ToIPC(),
		Command: cmd,
	}
	var fetched ipc.ExecFetchResp
	callErr := client.Call(ipc.OpExecFetch, req, &fetched)
	if callErr != nil {
		if isAuthRequiredErr(callErr) && scope.SourcePath == "" {
			// Ad-hoc exec auth_required. Non-TTY path: fail with actionable
			// hint (no --password-stdin for exec — it would break sub-command
			// argv parsing; run from a .byn dir to avoid the prompt entirely).
			if !stdinIsTTY() {
				fmt.Fprintf(os.Stderr, "%s ad-hoc exec requires authorization ([security] per_action_auth).\n", boldRed("Error:"))
				fmt.Fprintf(os.Stderr, "%s %s\n",
					dim("Hint:"), dim("run from a directory with a trusted .byn (credential-free), or unlock the vault's UI portal"))
				return exitDaemonErr
			}
			// Interactive TTY path: prompt once and retry.
			leadIn := yellow("Authorization required.") + dim(" [security] per_action_auth is on.")
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
		} else {
			return handleExecFetchError(callErr)
		}
	}
	renderAllowlistNotes(fetched, scope.SourcePath)

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
}
