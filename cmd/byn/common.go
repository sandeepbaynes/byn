package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Exit codes.
const (
	exitOK         = 0
	exitErr        = 1
	exitDaemonDown = 2
	exitDaemonErr  = 3
)

// defaultDir returns ~/.byn, or the BYN_DIR env override.
func defaultDir() (string, error) {
	if env := os.Getenv("BYN_DIR"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, ".byn"), nil
}

// newClient constructs an IPC client targeting the daemon's socket
// inside the configured data dir.
func newClient(dir string) *ipc.Client {
	return ipc.NewClient(filepath.Join(dir, daemon.SocketFilename))
}

// handleCallError consistently formats and routes IPC errors to the
// right exit code. The caller should `return handleCallError(err)`
// from any command handler.
func handleCallError(err error) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, ipc.ErrDaemonDown) {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red("byn daemon is not running."))
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Run:"), cyan("byn start"))
		return exitDaemonDown
	}
	var ipcErr *ipc.ErrResponse
	if errors.As(err, &ipcErr) {
		fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red(ipcErr.Message))
		if ipcErr.Recover != "" {
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Try:"), cyan(ipcErr.Recover))
		}
		return exitDaemonErr
	}
	fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
	return exitErr
}

// zero scrubs sensitive byte slices once we're done with them.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// stdinIsTTY reports whether stdin is an interactive terminal (vs a pipe or
// file). Used to decide between an interactive prompt and a non-interactive
// hard error.
func stdinIsTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// isLockedErr reports whether err is the daemon's "vault is locked" reply.
func isLockedErr(err error) bool {
	var er *ipc.ErrResponse
	return errors.As(err, &er) && er.Code == ipc.CodeLocked
}

// mutateWithLockRetry runs a key-free mutation (delete or rename) via
// call(nil) — the normal, already-unlocked path. If the daemon reports the
// vault is locked, it obtains the master password (from stdin when pwStdin is
// set, else an interactive secure prompt) and retries once with it. This
// authorizes the change WITHOUT unlocking the vault, so its values are never
// exposed to a process watching daemon memory. Returns a process exit code.
//
// call builds and issues the IPC request with the supplied password (nil on
// the first, unlocked attempt).
func mutateWithLockRetry(pwStdin bool, call func(password []byte) error) int {
	err := call(nil)
	if err == nil {
		return exitOK
	}
	if !isLockedErr(err) {
		return handleCallError(err)
	}
	pw, wipe, perr := authorizingPassword(pwStdin)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
		return exitErr
	}
	defer wipe()
	return handleCallError(call(pw))
}

// authorizingPassword obtains the master password used to authorize a
// key-free mutation on a locked vault. The returned wipe func MUST be
// deferred.
func authorizingPassword(pwStdin bool) (pw []byte, wipe func(), err error) {
	if pwStdin {
		pw, err = readPasswordStdin()
		if err != nil {
			return nil, func() {}, err
		}
		return pw, func() { zero(pw) }, nil
	}
	fmt.Fprintln(os.Stderr, yellow("Vault is locked.")+dim(" Enter the master password to authorize this."))
	fmt.Fprintln(os.Stderr, dim("The vault stays locked — its values are never exposed."))
	buf, err := auth.PromptStdinSecure("Master password: ")
	if err != nil {
		return nil, func() {}, err
	}
	return buf.Bytes(), buf.Wipe, nil
}
