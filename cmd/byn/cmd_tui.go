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
	"strings"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// tuiBinary is the program that draws the editor.
const tuiBinary = "byn-tui"

// tuiLibexecPath is where an installed byn keeps its editor.
//
// libexec, not bin, because this is byn's own helper rather than a command
// anybody runs: it takes no useful arguments, does nothing without a daemon, and
// putting it on PATH only offers a way to invoke it wrongly. byn already keeps
// its privileged spawn helper here for the same reason.
//
// A fixed path also means an installed byn always finds its editor, whatever the
// caller's PATH happens to be — including under sudo, whose secure_path is not
// the user's.
//
// A variable, not a constant, so a test can point it somewhere that does not
// exist. With a fixed absolute path these tests passed on any machine without
// byn installed and failed on any machine with it — including, eventually, this
// one. A test whose result depends on whether the product is installed is not
// testing the product.
var tuiLibexecPath = "/usr/local/libexec/" + tuiBinary

// execTUI replaces this process with the editor.
//
// A variable so a test can observe the launch instead of being destroyed by it.
// This is a real execve: a test that called runTUI on a machine where byn-tui
// happened to be installed had its own test binary replaced mid-run, which
// surfaced as a package failing with no failing test named — and only on a
// machine that had installed byn.
var execTUI = syscallExec

func runTUI(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("byn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}

	// Refuse before exec'ing, not after. The editor takes over the terminal;
	// with no terminal there is nothing to take over, and byn already knows
	// that. byn-tui checks again for its own sake — it can be run directly —
	// but replacing this process with one that will immediately refuse buys
	// nothing and makes the failure arrive from a program the user did not
	// name.
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "Error: byn TUI requires a terminal (stdout/stdin is piped or redirected)")
		return exitErr
	}

	path, err := findTUIBinary()
	if err != nil {
		// Missing only happens on the `go install` path — every packaged install
		// bundles the editor. So rather than print a command and stop, offer to
		// run it: the Go toolchain that installed byn is right there, and the
		// person is at a terminal by definition, since the editor needs one.
		if dest, derr := tuiInstallDest(); derr == nil {
			if got, ierr := offerTUIInstall(dest); ierr == nil {
				path = got
			} else if !strings.Contains(ierr.Error(), "declined") {
				fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), ierr)
			}
		}
	}
	if path == "" {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Fix:"), dim("install it with ")+cyan("go install "+tuiModuleRef()))
		fmt.Fprintf(os.Stderr, "%s %s\n", dim("     "),
			dim("or reinstall byn — every packaged install bundles the editor"))
		return exitErr
	}

	// Exec rather than spawn-and-wait: the editor owns the terminal for its
	// whole life, and a parent sitting in the middle would have to forward
	// every signal and resize correctly to add nothing. Replacing the process
	// makes byn-tui the terminal's foreground job directly, and its exit status
	// is byn's without a hop.
	argv := []string{path}
	argv = append(argv, tuiArgs(scope)...)
	if xerr := execTUI(path, argv, os.Environ()); xerr != nil {
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
	// byn's own directory first. An installed byn keeps the editor here, and
	// preferring it means a second copy left on PATH by an older install cannot
	// shadow the one that belongs to this byn.
	if usable(tuiLibexecPath) {
		return tuiLibexecPath, nil
	}
	if exe != "" {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		// Beside the running byn: the source build and `go install` case, where
		// nothing has been placed in libexec yet.
		if beside := filepath.Join(filepath.Dir(exe), tuiBinary); usable(beside) {
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

// usable reports whether path is an executable file we could actually run.
// A directory or a non-executable file of the right name is not the editor, and
// treating one as such trades a clear message for a permission error at exec.
func usable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode().Perm()&0o111 != 0
}

// tuiInstallDest is where a freshly built editor should land: beside the running
// byn, which is the second place findTUIBinaryNear looks.
//
// Beside byn rather than libexec because this path runs as the user, and libexec
// needs root. `byn setup` moves it to libexec later; until then, beside byn is
// found and works.
func tuiInstallDest() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	// Writable by us, or the install will fail after the download.
	if err := unix.Access(dir, unix.W_OK); err != nil {
		return "", fmt.Errorf("%s is not writable", dir)
	}
	return dir, nil
}
