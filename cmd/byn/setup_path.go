package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// privsepDaemonUserName names the service account in error messages.
var privsepDaemonUserName = privsep.DaemonUser

// systemBinDir is where byn belongs so that both your shell and sudo can find
// it. It is on the default PATH of every supported platform and inside sudo's
// secure_path, which ~/go/bin is not.
const systemBinDir = "/usr/local/bin"

// systemBinDirs are the locations that already count as "on the system PATH".
// A byn installed into any of these needs no help from us.
var systemBinDirs = []string{"/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/sbin"}

// ensureOnSystemPath makes the running byn reachable as plain `byn`.
//
// `go install` puts binaries in $(go env GOPATH)/bin — usually ~/go/bin, which
// is on no default PATH and, more awkwardly, is outside sudo's secure_path. The
// result was an install that produced a working binary nobody could run: `byn`
// was not a command, so there was no way to reach the very command that fixes
// it. The Go toolchain runs no install hook, so this cannot be done during
// `go install`; setup is the first moment byn has root and can.
//
// A COPY, not a symlink. A symlink into ~/.local/bin looks tidier and upgrades
// itself, but the daemon runs as the _byn service user, which cannot read
// inside a user's home — so systemd failed to exec it with "Permission denied"
// and the service never came up. The binary the service runs has to live
// somewhere the service user can read, which means a real file under
// /usr/local/bin. The cost is that a later `go install` needs `byn setup`
// re-run to be picked up; the packages do that automatically on upgrade.
func ensureOnSystemPath(stdout, stderr io.Writer) (installedAt string) {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if inSystemBinDir(exe) {
		return exe // already somewhere the service user can read
	}

	dest := filepath.Join(systemBinDir, "byn")
	if err := copyExecutable(exe, dest); err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: byn is installed at %s, which is not on the system PATH,\n", exe)
		_, _ = fmt.Fprintf(stderr, "         and it could not be linked into %s: %v\n", systemBinDir, err)
		_, _ = fmt.Fprintf(stderr, "         add %s to your PATH to run byn as `byn`.\n", filepath.Dir(exe))
		return ""
	}
	restoreSELinuxContext(dest)
	// The helper travels with it: the daemon execs it by absolute path, and it
	// is no more readable by the service user in a home directory than byn is.
	//
	// So does the editor. `byn edit` resolves byn-tui BESIDE the running byn, so
	// copying byn alone into a system path would leave a byn whose editor is not
	// there — working everywhere except the one command that needs a second
	// binary.
	for _, companion := range []string{"byn-exec-helper", tuiBinary} {
		src := filepath.Join(filepath.Dir(exe), companion)
		if !fileExists(src) {
			continue
		}
		dst := filepath.Join(systemBinDir, companion)
		if cerr := copyExecutable(src, dst); cerr == nil {
			restoreSELinuxContext(dst)
		}
	}
	_, _ = fmt.Fprintf(stdout, "installed %s (so `byn` works from any shell, under sudo, and for the service)\n", dest)
	return dest
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// inSystemBinDir reports whether path already lives somewhere on the PATH that
// a fresh shell and sudo both search.
func inSystemBinDir(path string) bool {
	dir := filepath.Dir(path)
	for _, d := range systemBinDirs {
		if dir == d {
			return true
		}
	}
	return false
}

// copyExecutable installs src at dest as a real file, readable and executable
// by everyone — including the service user, which is the whole point.
func copyExecutable(src, dest string) error {
	// 0755, not the 0750 gosec prefers: this is a system bin directory, and
	// every user on the machine has to be able to traverse it to run byn. A
	// mode that excluded them would defeat the point of putting byn there.
	// Normally a no-op — /usr/local/bin exists on every supported platform —
	// and only does anything on a stripped-down image.
	// #nosec G301
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	// Replace whatever is there — an older copy, or a symlink left by a byn
	// that used to install one. Removing first so a stale symlink is not
	// followed and written through.
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	in, err := os.Open(src) //nolint:gosec // src is this process's own executable
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //nolint:gosec // fixed system path
	if err != nil {
		return err
	}
	if _, cerr := io.Copy(out, in); cerr != nil {
		_ = out.Close()
		return cerr
	}
	return out.Close()
}

// restoreSELinuxContext relabels a freshly placed binary on SELinux systems.
// Best-effort: absent restorecon (or a machine without SELinux) is not an error,
// it just means there was no label to restore.
func restoreSELinuxContext(path string) {
	bin, err := exec.LookPath("restorecon")
	if err != nil {
		return
	}
	_ = exec.Command(bin, "-F", path).Run() //nolint:gosec // fixed binary, path is a fixed system location
}

// pathHint returns advice for a byn that is not reachable as `byn`, or "" when
// it is. Used by the first-run bootstrap, which cannot assume root.
func pathHint() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if inSystemBinDir(exe) {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == dir {
			return "" // on PATH for this shell at least
		}
	}
	return fmt.Sprintf("byn is installed at %s, which is not on your PATH.\n"+
		"Add it with:  export PATH=\"%s:$PATH\"   (or run `sudo %s setup`, which links it into %s)",
		exe, dir, exe, systemBinDir)
}

// sudoByn renders a `sudo byn …` command that will actually run.
//
// sudo resolves commands against secure_path — typically /usr/local/bin,
// /usr/bin, /bin and the sbins — and never the user's own PATH. A byn installed
// by `go install` lives in ~/go/bin (or wherever GOBIN points), so every
// message that said "run: sudo byn setup" was advice that could not be
// followed: sudo answered "byn: command not found", and the command being
// recommended was the one that fixes exactly this. Naming the absolute path
// costs nothing and always works.
func sudoByn(args ...string) string {
	name := "byn"
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		if !inSystemBinDir(exe) {
			name = exe
		}
	}
	if len(args) == 0 {
		return "sudo " + name
	}
	return "sudo " + name + " " + strings.Join(args, " ")
}

// serviceExecPath is the byn the systemd unit / LaunchDaemon should exec.
//
// Never a path inside a user's home: the daemon runs as the _byn service user,
// which cannot read there, and systemd reports that as a bare "Permission
// denied" at exec with the service flapping until it gives up. When byn is
// running from a home directory, the copy ensureOnSystemPath placed in
// /usr/local/bin is the one the service must use.
func serviceExecPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine byn executable path: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if inSystemBinDir(exe) {
		return exe, nil
	}
	dest := filepath.Join(systemBinDir, "byn")
	if fileExists(dest) {
		return dest, nil
	}
	return "", fmt.Errorf("byn runs from %s, which the %s service user cannot read, "+
		"and it could not be installed into %s", exe, privsepDaemonUserName, systemBinDir)
}
