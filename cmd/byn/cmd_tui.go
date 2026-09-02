// `byn` (no args) and `byn edit` / `byn view` launch the modal TUI, which lives
// in a separate binary.
//
// It is separate so that this one does not link bubbletea. bubbletea's package
// init calls lipgloss.HasDarkBackground(), which queries the terminal and waits
// up to five seconds for a reply — unconditionally, in every program that links
// it. On a terminal that answers, nothing is noticed. On a controlling terminal
// that does not (a pty with no emulator: `script`, serial consoles, CI runners
// that allocate a tty, some agent harnesses), it cost `byn version` 5.1 seconds,
// and every other command the same.
//
// Go initialises imported packages before the importing one, so byn cannot
// pre-empt a dependency's init from its own code. Not linking it is the only
// way not to run it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// tuiBinary is the program that draws the editor.
const tuiBinary = "byn-tui"

func runTUI(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("byn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}

	path, err := findTUIBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Fix:"),
			dim("reinstall byn, or run "+cyan(sudoByn("setup"))+" to place it next to byn"))
		return exitErr
	}

	// Exec rather than spawn-and-wait: the editor owns the terminal for its
	// whole life, and a parent sitting in the middle would have to forward
	// every signal and resize correctly to add nothing. Replacing the process
	// makes byn-tui the terminal's foreground job directly, and its exit status
	// is byn's without a hop.
	argv := []string{path}
	argv = append(argv, tuiArgs(scope)...)
	if xerr := syscallExec(path, argv, os.Environ()); xerr != nil {
		fmt.Fprintf(os.Stderr, "%s could not start %s: %v\n", boldRed("Error:"), tuiBinary, xerr)
		return exitErr
	}
	return exitOK // not reached on success
}

// tuiArgs passes the resolved scope explicitly rather than relying on the
// environment, so the editor opens the scope the user asked THIS command for —
// `byn --vault work edit` must open work, not whatever BYN_VAULT says.
func tuiArgs(scope cliScope) []string {
	var out []string
	if scope.Vault != "" {
		out = append(out, "--vault", scope.Vault)
	}
	if scope.Project != "" {
		out = append(out, "--project", scope.Project)
	}
	if scope.Env != "" {
		out = append(out, "--env", scope.Env)
	}
	return out
}

// findTUIBinary looks beside the running byn first, then on PATH.
//
// Beside-first is what makes a `go install`-ed byn and a packaged one each find
// their own editor rather than whichever happens to be earlier on PATH. Two byn
// installs of different versions on one machine is a situation `byn doctor`
// already reports, and it would be a poor answer to launch the wrong editor
// against the newer daemon.
func findTUIBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	return findTUIBinaryNear(exe)
}

// findTUIBinaryNear is findTUIBinary with the byn path injected, so a test can
// describe the machine it means rather than the one running it.
func findTUIBinaryNear(exe string) (string, error) {
	if exe != "" {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		beside := filepath.Join(filepath.Dir(exe), tuiBinary)
		if fi, serr := os.Stat(beside); serr == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0 {
			return beside, nil
		}
	}
	if p, err := exec.LookPath(tuiBinary); err == nil {
		return p, nil
	}
	return "", errors.New(tuiBinary + " was not found next to byn or on your PATH — " +
		"the editor ships as a separate binary")
}

// vaultStateByName looks up a named vault in a status snapshot. Kept here
// because other commands report vault state too.
func vaultStateByName(status ipc.StatusResp, name string) (locked, exists bool) {
	for _, v := range status.Vaults {
		if v.Name == name {
			return v.Locked, true
		}
	}
	return false, false
}

// defaultVaultState scans a StatusResp for the "default" vault.
func defaultVaultState(status ipc.StatusResp) (locked, exists bool) {
	return vaultStateByName(status, "default")
}
