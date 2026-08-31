package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

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

// parseFlags parses args allowing flags to appear after positional arguments.
//
// Go's flag package stops at the first non-flag argument, so `byn put NAME
// --password-stdin` left the flag unparsed and passed it on as the secret
// value — the form byn's own documentation recommends. Anything after a bare
// "--" is left alone, and args containing one are passed through untouched so
// separator-based commands keep their exact semantics.
func parseFlags(fs *flag.FlagSet, args []string) error {
	for _, a := range args {
		if a == "--" {
			return fs.Parse(args)
		}
	}

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		// A --flag=value token is self-contained: forward it whole and let
		// fs.Parse split it, rather than looking the name up here.
		if strings.IndexByte(name, '=') >= 0 {
			flags = append(flags, a)
			continue
		}
		f := fs.Lookup(name)
		// An unknown flag is forwarded as-is so fs.Parse reports it. A known
		// non-boolean flag also consumes the next token as its value.
		if f != nil && !isBoolFlag(f) && i+1 < len(args) {
			flags = append(flags, a, args[i+1])
			i++
			continue
		}
		flags = append(flags, a)
	}
	return fs.Parse(append(flags, positional...))
}

func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

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

// activeSocketPath resolves the socket the CLI connects to for a data dir,
// mirroring newClient's resolution (and fallback) so any path printed to the
// user is exactly the one we dial.
func activeSocketPath(dir string) string {
	sock, err := paths.ActiveSocketPath(dir)
	if err != nil {
		return filepath.Join(dir, daemon.SocketFilename)
	}
	return sock
}

// newClient constructs an IPC client targeting the daemon's socket. The socket
// location is resolved by paths.ActiveSocketPath — the SAME helper the daemon
// binds through — so connect and bind can never disagree: the runtime socket
// when this install is provisioned (an owner record exists), else the legacy
// socket inside the data dir (no behavior change for today's installs — spec
// D3). A resolution error (a filesystem glitch statting the owner record) falls
// back to the data-dir socket, matching the unprovisioned default.
//
// When vault is non-empty (or "default"), a session token for the current TTY +
// vault is loaded from disk and attached to the client so the daemon can
// authorize without re-prompting.
func newClient(dir, vault string) *ipc.Client {
	sock, err := paths.ActiveSocketPath(dir)
	if err != nil {
		sock = filepath.Join(dir, daemon.SocketFilename)
	}
	c := ipc.NewClient(sock)
	key := vaultSessionKey(vault)
	if tok := loadSessionToken(sessionStoreDir(dir), key); len(tok) > 0 {
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
		cmd, note := daemonDownRemedy(cliPrivsepProvisioned())
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Run:"), cyan(cmd))
		if note != "" {
			fmt.Fprintf(os.Stderr, "%s\n", dim(note))
		}
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
	// term.IsTerminal, not a character-device test.
	//
	// The character-device test called /dev/null a terminal, because it is one
	// — a character device that is not a terminal. That is the canonical stdin
	// of an unattended process, so byn classified exactly the callers it most
	// needed to recognise as people sitting at a keyboard: it offered them a
	// password prompt, the prompt refused (term.IsTerminal, correctly, said no),
	// and the caller got two lines of noise ahead of the reason it was actually
	// refused.
	//
	// The prompt and this check must ask the same question, or byn decides to
	// prompt on one answer and then fails on the other.
	return term.IsTerminal(int(os.Stdin.Fd()))
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

	// A first command against a vault that does not exist yet is not a failure
	// to report — it is a vault the user has just asked for. Create it (with a
	// password they choose) and run what they actually typed.
	if isNotInitErr(err) {
		if c := firstRunClient; c != nil && offerVaultInit(c, firstRunVault, jsonMode) {
			if err = call(nil); err == nil {
				return exitOK
			}
		}
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
		// The daemon refused: exit 3, the same as every other refusal.
		//
		// This returned 1, which byn documents as "bad usage" and every other
		// command uses for exactly that. So `byn delete --json X` exited 1 on a
		// refusal while `byn put --json X` exited 3 on the identical refusal,
		// and an agent branching on the code was told its arguments were wrong
		// when it had been refused authorization — the one distinction that
		// decides whether asking for a credential is worth trying.
		return exitDaemonErr
	}

	// If the vault is locked and this op cannot proceed while locked, fail fast
	// with the standard locked rendering (handleCallError prints the daemon's
	// message + recover hint, which is already "byn unlock"). This covers the
	// non-JSON paths for get/put (overwrite)/entry-rename.
	if locked && !retryOnLocked {
		return handleCallError(err)
	}

	// Nobody to prompt: say why the command was refused and stop.
	//
	// This used to invite a password first and discover there was no terminal
	// second, so an unattended caller got three lines — "Enter the master
	// password", "auth: not a terminal", and only then the daemon's actual
	// reason. Two of them addressed to a person who was not there, and the one
	// that explains the refusal last. handleCallError prints the reason and the
	// recovery hint, which is what a caller can act on.
	if !pwStdin && !stdinIsTTY() {
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
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
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

// firstRunClient / firstRunVault let mutateWithAuthRetry reach the daemon to
// create a missing vault. They are set by the command handlers that already
// build a client, rather than threaded through every call site, because the
// retry helper is shared by a dozen commands whose signatures would otherwise
// all have to change for this one case.
var (
	firstRunClient *ipc.Client
	firstRunVault  string
)

// setFirstRunTarget records which client and vault a lazy init should use.
func setFirstRunTarget(c *ipc.Client, vault string) {
	firstRunClient, firstRunVault = c, vault
}

// daemonDownRemedy returns the command that will actually bring the daemon back,
// and a note explaining why it needs root when it does.
//
// Where byn runs under a service user, `byn start` refuses and prints a
// DIFFERENT command — so naming it here cost the reader a round trip to learn
// something byn already knew. A recovery hint that does not recover is worse
// than none: it spends the reader's trust before the real answer arrives.
func daemonDownRemedy(privsepProvisioned bool) (cmd, note string) {
	if privsepProvisioned {
		return "sudo byn restart", "(it runs as the _byn service, so bringing it up needs root)"
	}
	return "byn start", ""
}
