package auth

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/sandeepbaynes/byn/internal/secmem"
)

// ErrNoTerminal is returned by Prompt when fd doesn't refer to a
// terminal — most often because input is piped or redirected.
var ErrNoTerminal = errors.New("auth: not a terminal")

// Prompt writes prompt to w (typically os.Stderr) and reads a
// password from fd (typically os.Stdin's fd) without echoing.
// Returns the raw bytes; the caller is responsible for zeroing them
// after use.
//
// The terminal's echo state is restored even if the read is
// interrupted (SIGINT).
func Prompt(fd int, w io.Writer, prompt string) ([]byte, error) {
	if !term.IsTerminal(fd) {
		return nil, ErrNoTerminal
	}
	if _, err := fmt.Fprint(w, prompt); err != nil {
		return nil, err
	}
	pw, err := term.ReadPassword(fd)
	// Newline after the (silent) password input so the next stderr
	// line doesn't run on the prompt line.
	_, _ = fmt.Fprintln(w)
	if err != nil {
		return nil, fmt.Errorf("auth: read password: %w", err)
	}
	return pw, nil
}

// PromptStdin is a convenience that reads from os.Stdin and writes
// the prompt to os.Stderr.
func PromptStdin(prompt string) ([]byte, error) {
	return Prompt(int(os.Stdin.Fd()), os.Stderr, prompt)
}

// PromptStdinSecure is the mlock'd-buffer variant of PromptStdin. The
// password is read into a secmem.Buffer (pages mlocked where the
// platform supports it) and zeroed on Wipe. Callers MUST call
// buf.Wipe() when done — typically via defer.
//
// The intermediate term.ReadPassword still returns a plain []byte;
// we copy into the secmem buffer immediately and zero the temporary.
// Short window, but documented honestly: the password is mlock'd
// from copy onward; never NOT mlock'd in the daemon's heap after
// receipt over IPC (see SPEC §9.3 — the daemon-side Argon2
// workspace + vault key are not yet wrapped in secmem).
func PromptStdinSecure(prompt string) (*secmem.Buffer, error) {
	raw, err := Prompt(int(os.Stdin.Fd()), os.Stderr, prompt)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Best-effort zero of the temporary even on error paths.
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) == 0 {
		// secmem.NewBuffer rejects size 0. Return a Buffer-shaped
		// nil so callers' .Bytes() path still works for "empty"
		// passwords; though in practice the unlock will fail.
		return secmem.NewBuffer(1)
	}
	return secmem.NewBufferFrom(raw)
}

// ttyDevice is the process's controlling terminal. Reading a password from it
// rather than from stdin is what lets a command whose stdin carries data still
// ask a person a question.
const ttyDevice = "/dev/tty"

// PromptTTY reads a password from the controlling terminal, regardless of what
// stdin is connected to.
//
// It exists because stdin is not always free. `echo "$V" | byn put NAME` hands
// the value in on stdin, so when the daemon then asks for authorization there is
// nothing left to prompt on — and byn told a person sitting at a terminal to go
// run `byn unlock`, because it had checked the wrong file descriptor for their
// presence. stdin says how data arrived; it does not say whether anybody is
// there.
//
// This is what sudo, ssh, git and gpg all do for the same reason. Returns
// ErrNoTerminal when there is no controlling terminal — a cron job, a container,
// a CI runner — which is the honest answer there and leaves the caller free to
// report the refusal instead of hanging on a prompt nobody can answer.
//
// The prompt is written to the terminal too, not to stderr: a caller redirecting
// stderr to a file should not have the question it is waiting on land in the
// file rather than on the screen.
func PromptTTY(prompt string) ([]byte, error) { return promptTTYWithLead(prompt, nil) }

// openTTY opens the controlling terminal. A variable rather than a direct call
// so a test can supply one: /dev/tty is a fixed path with no seam, and a test
// binary usually has no controlling terminal at all — which would leave the
// interesting branch skipped exactly where it most needs covering.
var openTTY = func() (*os.File, error) { return os.OpenFile(ttyDevice, os.O_RDWR, 0) }

func promptTTYWithLead(prompt string, lead []string) ([]byte, error) {
	tty, err := openTTY()
	if err != nil {
		return nil, ErrNoTerminal
	}
	defer func() { _ = tty.Close() }()
	for _, l := range lead {
		if _, werr := fmt.Fprintln(tty, l); werr != nil {
			return nil, werr
		}
	}
	return Prompt(int(tty.Fd()), tty, prompt)
}

// PromptTTYSecure is PromptTTY into an mlock'd buffer. Callers MUST Wipe it.
func PromptTTYSecure(prompt string) (*secmem.Buffer, error) {
	return PromptTTYSecureWithLead(prompt, nil)
}

// PromptTTYSecureWithLead writes lead lines to the terminal before the prompt,
// so the explanation for a question lands where the question does. A caller
// that has redirected stderr should not have the reason it is being asked go
// into the redirect while the prompt waits on screen.
func PromptTTYSecureWithLead(prompt string, lead []string) (*secmem.Buffer, error) {
	raw, err := promptTTYWithLead(prompt, lead)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) == 0 {
		return secmem.NewBuffer(1)
	}
	buf, err := secmem.NewBuffer(len(raw))
	if err != nil {
		return nil, err
	}
	copy(buf.Bytes(), raw)
	return buf, nil
}

// HaveTerminal reports whether a person can be asked a question at all: either
// stdin is a terminal, or the process has a controlling terminal to fall back
// to. It is the question "is anybody there", which is not the same question as
// "did data arrive on a pipe".
func HaveTerminal(stdinFd int) bool {
	if term.IsTerminal(stdinFd) {
		return true
	}
	tty, err := openTTY()
	if err != nil {
		return false
	}
	isTTY := term.IsTerminal(int(tty.Fd()))
	_ = tty.Close()
	return isTTY
}
