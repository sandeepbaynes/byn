package main

// Pager: route long-form output (help blobs, --help, man-style usage)
// through $PAGER when stdout is a TTY, so users on terminals without
// scrollback can page through with j/k/Space/q like man and aws help.
//
// Rules (match git/man/aws):
//   - stdout is NOT a TTY (pipe, redirect, CI)        → write directly
//   - stdin is NOT a TTY (script feeding byn)      → write directly
//   - env BYN_NO_PAGER=1                           → write directly
//   - env PAGER set                                   → use that
//   - else: `less -R -F -X` (auto-quit if one screen, no clear on exit)
//   - if exec fails (e.g. less not installed)         → fall back to direct write
//
// The -R flag preserves ANSI colors; -F exits if the content fits a
// single screen (mimics aws-cli behavior); -X preserves the help text
// in the terminal after quit instead of clearing it.

import (
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// fprintPaged writes text to w. If w is os.Stdout AND is a TTY AND
// stdin is also a TTY AND BYN_NO_PAGER is not set, it spawns a
// pager and writes to that pager's stdin instead. Any failure to
// launch the pager falls back to a direct write.
func fprintPaged(w *os.File, text string) {
	if !shouldPage(w) {
		_, _ = io.WriteString(w, text)
		return
	}
	pagerCmd := pickPager()
	if pagerCmd == nil {
		_, _ = io.WriteString(w, text)
		return
	}
	stdin, err := pagerCmd.StdinPipe()
	if err != nil {
		_, _ = io.WriteString(w, text)
		return
	}
	pagerCmd.Stdout = w
	pagerCmd.Stderr = os.Stderr
	if err := pagerCmd.Start(); err != nil {
		_ = stdin.Close()
		_, _ = io.WriteString(w, text)
		return
	}
	// Write may fail if the user quits the pager mid-stream — that's
	// the user's choice, not an error to report.
	_, _ = io.WriteString(stdin, text)
	_ = stdin.Close()
	_ = pagerCmd.Wait()
}

func shouldPage(w *os.File) bool {
	if w != os.Stdout {
		return false
	}
	if os.Getenv("BYN_NO_PAGER") == "1" {
		return false
	}
	// PAGER=cat is the documented "disable pager" convention.
	if os.Getenv("PAGER") == "cat" {
		return false
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	return true
}

// pickPager builds the *exec.Cmd to run as the pager, or nil if no
// usable pager was found.
func pickPager() *exec.Cmd {
	if p := os.Getenv("PAGER"); p != "" {
		// Honor whatever the user set, including custom flags
		// (e.g. PAGER="less -SR").
		fields := strings.Fields(p)
		if len(fields) == 0 {
			return nil
		}
		return exec.Command(fields[0], fields[1:]...) //nolint:gosec // user-chosen pager via $PAGER
	}
	// Default to less with man-page-friendly flags. -R: keep ANSI;
	// -F: exit if content fits one screen; -X: don't clear on quit.
	if _, err := exec.LookPath("less"); err == nil {
		return exec.Command("less", "-R", "-F", "-X")
	}
	if _, err := exec.LookPath("more"); err == nil {
		return exec.Command("more")
	}
	return nil
}
