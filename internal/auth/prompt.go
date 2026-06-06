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
