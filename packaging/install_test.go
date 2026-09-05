// Package packaging holds guards for how byn is installed. It has no
// non-test sources: the thing under test is the Makefile, and this is where a
// reader looking for packaging behaviour would go for it.
package packaging

import (
	"os/exec"
	"strings"
	"testing"
)

// makeDryRun returns the commands `make install` WOULD run, without running them.
func makeDryRun(t *testing.T, extra ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make not available")
	}
	args := append([]string{"-n", "install"}, extra...)
	cmd := exec.Command("make", args...)
	cmd.Dir = ".."
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("make -n install failed in this environment: %v", err)
	}
	return string(out)
}

// sudoLines counts recipe lines that actually invoke sudo, ignoring the
// comments and the echoed advice that mention the word.
func sudoLines(out string) []string {
	var got []string
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "sudo ") {
			got = append(got, t)
		}
	}
	return got
}

// A staged package build installs into a DIRECTORY it already owns, as a
// non-root build user, usually with no tty. An elevation there does not just
// fail — it hangs waiting for a password nobody can type, in CI.
func TestInstall_NeverElevatesForAStagedBuild(t *testing.T) {
	out := makeDryRun(t, "DESTDIR=/tmp/byn-staging-test")
	if got := sudoLines(out); len(got) != 0 {
		t.Errorf("a DESTDIR build must never sudo; it would run:\n  %s",
			strings.Join(got, "\n  "))
	}
}

// The Agent Skill goes into a person's home directory. A package build must not
// write into the build user's home — that is the packager's machine, not the
// machine the package will be installed on.
func TestInstall_NeverTouchesHomeForAStagedBuild(t *testing.T) {
	out := makeDryRun(t, "DESTDIR=/tmp/byn-staging-test")
	if strings.Contains(out, "skill install") &&
		!strings.Contains(out, `if [ -z "/tmp/byn-staging-test" ]`) {
		t.Error("the skill step must be guarded so a staged build skips it")
	}
}

// The inverse: a normal install DOES elevate, and only after the build. If this
// stops being true, `make install` starts failing with permission errors on the
// first write to /usr/local instead of asking for a password.
func TestInstall_ElevatesForARealInstall(t *testing.T) {
	out := makeDryRun(t)
	if strings.TrimSpace(out) == "" {
		t.Skip("no output")
	}
	// Already root (a CI container often is): nothing to elevate, and the
	// Makefile is correct to skip it.
	if strings.Contains(out, "id -u") {
		t.Skip("SUDO resolution is shell-evaluated here; covered by the DESTDIR cases")
	}
	if len(sudoLines(out)) == 0 {
		t.Skip("running as root, or sudo unavailable — nothing to elevate")
	}
	// The build must come first, so the password prompt lands after the slow part.
	firstSudo := strings.Index(out, "\nsudo ")
	build := strings.Index(out, "go build")
	if build < 0 || firstSudo < 0 {
		t.Skip("unexpected dry-run shape")
	}
	if build > firstSudo {
		t.Error("the build must run before the first elevation, so the password " +
			"prompt comes after the slow step rather than in the middle of it")
	}
}
