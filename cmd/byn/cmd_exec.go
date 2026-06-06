package main

import (
	"fmt"
	"os"
	"os/exec"
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
//     OpGet response and the exec syscall. After exec, our process
//     image is replaced and the strings are gone with it. (Best-effort
//     hygiene; values do briefly exist as Go strings in our heap.)
//
// Limitations of v1 (intentional, to be iterated on):
//
//   - N+1 IPC round-trips (one List + one Get per entry). A future
//     OpExecPrep op can return all values in one frame; deferred until
//     we have a real perf signal.
//   - injected values briefly exist as Go strings in heap between
//     OpGet and syscall.Exec. Mitigatable later with secmem + a
//     direct execve wrapper; not worth the cgo for v1.
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

	// Stage 1: list env-var entries in the active scope.
	scopeIPC := scope.ToIPC()
	var listResp ipc.ListResp
	if err := client.Call(ipc.OpList, ipc.ListReq{Scope: scopeIPC}, &listResp); err != nil {
		return handleCallError(err)
	}

	// Stage 2: fetch each entry's value. N+1 round-trips; fine for
	// v1, replaceable with a getMany op when perf signal appears.
	//
	// Values land in our heap as Go strings (KEY=value). We zero the
	// underlying byte slices from the IPC responses immediately, but
	// the constructed env strings persist until syscall.Exec replaces
	// the process image.
	extraEnv := make([]string, 0, len(listResp.Secrets))
	for _, meta := range listResp.Secrets {
		var got ipc.GetResp
		if err := client.Call(ipc.OpGet, ipc.GetReq{Scope: scopeIPC, Name: meta.Name}, &got); err != nil {
			return handleCallError(err)
		}
		extraEnv = append(extraEnv, meta.Name+"="+string(got.Value))
		// Wipe the response buffer; the env-string copy is already
		// made.
		for i := range got.Value {
			got.Value[i] = 0
		}
	}

	// Stage 3: resolve the binary in PATH. We do this BEFORE the env
	// merge so a missing binary fails fast with a clear message,
	// without ever materializing the env vars in a syscall.
	cmdPath, err := exec.LookPath(childArgv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	// Stage 4: build the env. Parent's environ first so injected vars
	// can shadow it (last value wins per POSIX, and most shells/libs
	// follow that). This means a stored DB_URL overrides any DB_URL
	// already exported in the parent shell — usually what the user
	// wants.
	envv := append(os.Environ(), extraEnv...)

	// Stage 5: replace the process. On success, this never returns.
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
