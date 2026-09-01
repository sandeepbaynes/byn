package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/term"
)

// elevationGuard marks a byn that was started by our own sudo re-exec.
//
// Without it a sudo that does not actually elevate — a policy that permits the
// command but maps it to the same user, a broken wrapper — would have byn
// re-exec itself for ever. One env var turns an infinite loop into a single
// honest error.
const elevationGuard = "BYN_SETUP_ELEVATED"

// elevateWithSudo re-runs `byn setup` under sudo so the caller is prompted for
// their password, rather than being told to retype the command themselves.
//
// Reports whether it took over: false means sudo is unavailable or we are
// already the product of an elevation attempt, and the caller should fall back
// to printing the command to run.
//
// The path re-executed is this process's own resolved executable, never a name
// looked up on PATH — the whole point is to run *this* byn as root, and
// resolving through PATH under sudo's secure_path could find a different one.
func elevateWithSudo(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, bool) {
	if os.Getenv(elevationGuard) != "" {
		return 0, false // we already tried; sudo did not get us to root
	}
	// Only when there is somebody to ask. sudo prompts on the terminal, so
	// without one this hangs until it times out — which is what it did to a
	// unit test, and would do to any script or CI job that ran byn setup. A
	// caller with no terminal gets the command to run instead, which it can act
	// on; a prompt it cannot answer is worse than a message it can read.
	if !readerIsTTY(stdin) {
		return 0, false
	}
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return 0, false
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, false
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}

	// Said before the prompt appears. An unexplained password prompt is alarming
	// and teaches people to type their password at anything that asks.
	_, _ = fmt.Fprintf(stderr, "%s %s\n", yellow("byn setup needs root."),
		dim("re-running as "+"sudo "+exe+" setup — you may be asked for your password."))

	argv := append([]string{"--", exe, "setup"}, args...)
	cmd := exec.Command(sudoPath, argv...) //nolint:gosec // sudo from PATH, then this process's own resolved path
	cmd.Env = append(os.Environ(), elevationGuard+"=1")
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if rerr := cmd.Run(); rerr != nil {
		var exitErrType *exec.ExitError
		if errors.As(rerr, &exitErrType) {
			// sudo itself reported why (wrong password, not a sudoer,
			// cancelled, no terminal to prompt on). Its message is the accurate
			// one, so it stands — but sudo cannot know what byn was trying to
			// do, and a caller left with only "a terminal is required" has
			// nothing to act on. Passing the code through keeps a script's view
			// of the failure accurate instead of flattening everything to 1.
			_, _ = fmt.Fprintln(stderr, yellow("Run:")+" "+cyan(sudoByn("setup")))
			return exitErrType.ExitCode(), true
		}
		_, _ = fmt.Fprintf(stderr, "%s could not run sudo: %v\n", boldRed("Error:"), rerr)
		return exitErr, true
	}
	return exitOK, true
}

// readerIsTTY reports whether r is a terminal byn could prompt on. Anything
// that is not an *os.File — a test buffer, a pipe — is not.
func readerIsTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
