package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/paths"
)

// Exit codes.
const (
	exitOK         = 0
	exitErr        = 1
	exitDaemonDown = 2
	exitDaemonErr  = 3
)

// defaultDir returns the active data root (internal/paths): the fixed per-OS
// system path once an install is provisioned there, else the legacy per-user
// ~/.byn (preserving today's behavior while privsep is opt-in-off — spec D3).
// There is no runtime env override in a production build — a repointable data
// root is attack surface (spec §6.5); tests isolate a tempdir via the byntest
// build tag (paths.DataDir honors BYN_TEST_DIR only there). The error covers an
// undiscoverable home dir on the legacy branch.
func defaultDir() (string, error) {
	return paths.DataDir()
}

// newClient constructs an IPC client targeting the daemon's socket
// inside the configured data dir. When vault is non-empty (or "default"),
// a session token for the current TTY + vault is loaded from disk and
// attached to the client so the daemon can authorize without re-prompting.
func newClient(dir, vault string) *ipc.Client {
	c := ipc.NewClient(filepath.Join(dir, daemon.SocketFilename))
	key := vaultSessionKey(vault)
	if tok := loadSessionToken(dir, key); len(tok) > 0 {
		c.Session = tok
	}
	return c
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

// isAuthRequiredErr reports whether err is the daemon's auth gate reply.
func isAuthRequiredErr(err error) bool {
	var er *ipc.ErrResponse
	return errors.As(err, &er) && er.Code == ipc.CodeAuthRequired
}

// mutateWithAuthRetry is the unified retry helper for IPC operations that may
// require authorization. On first call it tries with no password; on a gated
// response it either prompts (TTY path) or reads from stdin and retries once.
// In jsonMode it never prompts — it prints an actionable error and returns
// exitErr.
//
// retryOnLocked controls whether a CodeLocked response triggers the
// password-and-retry path:
//
//   - true  — delete-family operations that support authorizeMutationWhileLocked
//     (entry delete, env delete/clear, project delete, vault delete, and the
//     rename variants). A locked vault can be operated on by supplying the
//     master password: the daemon verifies without unlocking.
//   - false — get / put (overwrite) / entry rename. A correct password still
//     yields CodeLocked because those ops need the vault key in memory. The
//     retry loop is a dead end; fail fast with the standard locked rendering
//     and "byn unlock" hint instead.
//
// call builds and issues the IPC request with the supplied password (nil on
// the first attempt, non-nil on the retry).
func mutateWithAuthRetry(pwStdin bool, jsonMode bool, retryOnLocked bool, cleanupOnAuthRequired func(), call func(password []byte) error) int {
	err := call(nil)
	if err == nil {
		return exitOK
	}

	locked := isLockedErr(err)
	authRequired := isAuthRequiredErr(err)

	if !locked && !authRequired {
		return handleCallError(err)
	}

	// Call cleanup hook before prompting (clears a stale session file if any).
	if (locked || authRequired) && cleanupOnAuthRequired != nil {
		cleanupOnAuthRequired()
	}

	// JSON guard (no piped password): never prompt; print an actionable
	// message and exit. Branch on the specific gate.
	if jsonMode && !pwStdin {
		if locked {
			fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"), red("vault is locked"))
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Run:"), cyan("byn unlock"))
		} else {
			fmt.Fprintf(os.Stderr, "%s %s\n", boldRed("Error:"),
				red("authorization required"))
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Use:"), cyan("--password-stdin"))
		}
		return exitErr
	}

	// If the vault is locked and this op cannot proceed while locked, fail fast
	// with the standard locked rendering (handleCallError prints the daemon's
	// message + recover hint, which is already "byn unlock"). This covers the
	// non-JSON paths for get/put (overwrite)/entry-rename.
	if locked && !retryOnLocked {
		return handleCallError(err)
	}

	var leadIn string
	if locked {
		leadIn = yellow("Vault is locked.") + dim(" Enter the master password to authorize this.")
	} else {
		leadIn = yellow("Authorization required.") + dim(" Enter the master password to authorize.")
	}
	pw, wipe, perr := authorizingPasswordWithLeadIn(pwStdin, leadIn)
	if perr != nil {
		// If we can't prompt (non-TTY, no --password-stdin), propagate the
		// daemon's typed error rather than a generic exit-1.  The caller
		// already printed the daemon error above; print the prompt failure so
		// the user knows WHY we couldn't re-auth, then surface the exit code.
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
		if !pwStdin && !stdinIsTTY() {
			// Non-interactive: return the daemon error code (3) so scripts
			// and tests can distinguish "needs auth" from generic failure.
			return handleCallError(err)
		}
		return exitErr
	}
	defer wipe()
	return handleCallError(call(pw))
}

// authorizingPasswordWithLeadIn obtains the master password for a locked-vault
// or auth-gated operation. leadIn is printed before the prompt when
// stdin is a TTY. The returned wipe func MUST be deferred.
func authorizingPasswordWithLeadIn(pwStdin bool, leadIn string) (pw []byte, wipe func(), err error) {
	if pwStdin {
		pw, err = readPasswordStdin()
		if err != nil {
			return nil, func() {}, err
		}
		return pw, func() { zero(pw) }, nil
	}
	fmt.Fprintln(os.Stderr, leadIn)
	if strings.Contains(leadIn, "locked") {
		fmt.Fprintln(os.Stderr, dim("The vault stays locked — its values are never exposed."))
	}
	buf, err := auth.PromptStdinSecure("Master password: ")
	if err != nil {
		return nil, func() {}, err
	}
	return buf.Bytes(), buf.Wipe, nil
}
