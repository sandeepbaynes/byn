package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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
// A symlink rather than a copy, so a later `go install ...@latest` is picked up
// without re-running setup. Falls back to a copy where symlinking fails.
func ensureOnSystemPath(stdout, stderr io.Writer) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}
	if inSystemBinDir(exe) {
		return // already reachable; nothing to do
	}

	dest := filepath.Join(systemBinDir, "byn")
	// If something is already there pointing at us, we are done.
	if current, lerr := filepath.EvalSymlinks(dest); lerr == nil && current == exe {
		return
	}
	if err := linkOrCopy(exe, dest); err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: byn is installed at %s, which is not on the system PATH,\n", exe)
		_, _ = fmt.Fprintf(stderr, "         and it could not be linked into %s: %v\n", systemBinDir, err)
		_, _ = fmt.Fprintf(stderr, "         add %s to your PATH to run byn as `byn`.\n", filepath.Dir(exe))
		return
	}
	restoreSELinuxContext(dest)
	_, _ = fmt.Fprintf(stdout, "linked %s -> %s (so `byn` works from any shell, and under sudo)\n", dest, exe)
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

// linkOrCopy points dest at src, preferring a symlink so upgrades to src are
// picked up without re-running setup.
func linkOrCopy(src, dest string) error {
	// 0755, not the 0750 gosec prefers: this is a system bin directory, and
	// every user on the machine has to be able to traverse it to run byn. A
	// mode that excluded them would defeat the point of putting byn there.
	// Normally a no-op — /usr/local/bin exists on every supported platform —
	// and only does anything on a stripped-down image.
	// #nosec G301
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	// Replace whatever is there: an older link, or a byn from a previous
	// install. Removing first because os.Symlink refuses an existing name.
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(src, dest); err == nil {
		return nil
	}
	// A filesystem that cannot symlink, or a policy that forbids it: copy.
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
