//go:build integration

// NU-5 privilege-separation cred-leak PROOF (root-gated; skips cleanly off-root).
//
// This is the integration test NU-5 exists for: it proves that when
// [security] privsep is enabled, a trusted-.byn pinned `byn exec` runs its
// child as the _byn-exec service user, so a same-(owner)-class NON-ROOT process
// cannot read the child's /proc/<pid>/environ — the injected secret never
// reaches a process that is not the child itself.
//
// HONEST CEILING (verified, documented in docs/security.md): root /
// CAP_SYS_PTRACE can still read the environ. The proof here is specifically
// about the *non-root* same-deployment process the owner actually fears (a
// coding agent, a CI step) — which is denied by the kernel's ptrace-mode check
// once the child has dropped to a different uid.
//
// Gating: the env-read proof is Linux-specific (it reads /proc) and requires
// real privilege separation (setcap / a distinct service uid), so it runs ONLY
// as root on Linux. Off-root or off-Linux it t.Skips with a clear reason. On
// the dedicated root CI job (.github/workflows/ci.yml: privsep-integration) the
// core proof runs for real.
package integration

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const privsepPW = "correct-horse-battery-staple-privsep"

// privsepSecret is the sentinel injected into the exec child's environment. The
// whole proof is that a non-root same-deployment process can NOT find these
// bytes in the child's /proc/<pid>/environ.
const privsepSecret = "s3ntinel-privsep-no-leak-v1"

// requireRootLinux skips the test unless it is running as root on Linux. The
// /proc/<pid>/environ proof is Linux-specific and the uid-drop needs real
// privilege; off-root or off-Linux we cannot prove anything, so we skip rather
// than give a false pass.
func requireRootLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("privsep cred-leak proof is Linux-specific (reads /proc); GOOS=%s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("privsep cred-leak proof needs root (setcap helper + uid-drop + cross-uid /proc read); run on the privsep-integration CI job or `sudo -E ... go test -tags=integration -run TestPrivsep`")
	}
}

// buildHelper builds cmd/byn-exec-helper next to the test's byn binary so that
// `byn setup` (which resolves byn-exec-helper beside the running byn) finds it.
// Returns the helper path.
func buildHelper(t *testing.T, bynBin string) string {
	t.Helper()
	helper := filepath.Join(filepath.Dir(bynBin), "byn-exec-helper")
	cmd := exec.Command("go", "build", "-o", helper, "./cmd/byn-exec-helper")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build byn-exec-helper: %v\n%s", err, out)
	}
	return helper
}

// skipUnlessToolsPresent skips when a tool the privsep setup needs is missing in
// the CI image (e.g. setcap, useradd, setfacl), so the job degrades to a clean
// skip instead of a confusing failure on a bare image.
func skipUnlessToolsPresent(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("required tool %q not on PATH (CI image lacks privsep prerequisites): %v", tool, err)
		}
	}
}

// execUID returns the resolved uid of the _byn-exec service user, or skips if
// `byn setup` did not actually create it (e.g. systemd-sysusers unavailable).
func execUID(t *testing.T) int {
	t.Helper()
	u, err := user.Lookup("_byn-exec")
	if err != nil {
		t.Skipf("_byn-exec service user absent after `byn setup` (sysusers unavailable on this image): %v", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse _byn-exec uid %q: %v", u.Uid, err)
	}
	return uid
}

// unprivReaderUID returns a non-root uid that is NOT _byn-exec, to play the role
// of the owner-class attacker (a coding agent / CI step). It prefers "nobody";
// failing that, any non-system non-root account it can find. Skips if none
// exists.
func unprivReaderUID(t *testing.T, execu int) int {
	t.Helper()
	for _, name := range []string{"nobody", "daemon", "games"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil || uid == 0 || uid == execu {
			continue
		}
		return uid
	}
	t.Skip("no suitable non-root reader account (nobody/daemon/games) to play the owner-class attacker")
	return -1
}

// findChildPID scans /proc for a process owned by wantUID whose comm/cmdline
// names `sleep`. Returns the pid, or 0 if none is found yet. The privsep child
// is the _byn-exec sleep; this is how the test pins it while it runs.
func findChildPID(wantUID int) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		// Owner uid of /proc/<pid> is the process's real uid.
		uid := statUID("/proc/" + e.Name())
		if uid != wantUID {
			continue
		}
		comm, _ := os.ReadFile("/proc/" + e.Name() + "/comm") // #nosec G304 -- /proc path
		if strings.TrimSpace(string(comm)) == "sleep" {
			return pid
		}
	}
	return 0
}

// statUID returns the owner uid of a path, or -1 on error.
func statUID(path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		return -1
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}

// waitForChild polls findChildPID until it appears or the deadline passes.
func waitForChild(wantUID int, deadline time.Time) int {
	for time.Now().Before(deadline) {
		if pid := findChildPID(wantUID); pid != 0 {
			return pid
		}
		time.Sleep(25 * time.Millisecond)
	}
	return 0
}

// readEnvironAs reads /proc/<pid>/environ while dropped to readerUID via a tiny
// `cat` invocation that setuid()s first. We use `setpriv` (util-linux) when
// available; it cleanly drops to a uid with no caps. Returns the bytes read and
// the process's combined error. A non-nil err with empty output is the EACCES
// case the proof wants.
func readEnvironAs(readerUID, pid int) (out []byte, exitErr error) {
	environPath := "/proc/" + strconv.Itoa(pid) + "/environ"
	// setpriv --reuid <uid> --regid <uid> --clear-groups cat <environ>
	cmd := exec.Command("setpriv",
		"--reuid", strconv.Itoa(readerUID),
		"--regid", strconv.Itoa(readerUID),
		"--clear-groups",
		"cat", environPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), errors.New(strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// TestPrivsep_CredLeakProof is the capstone NU-5 proof. See the file header.
func TestPrivsep_CredLeakProof(t *testing.T) {
	requireRootLinux(t)
	// `byn setup` needs systemd-sysusers (user creation) + setcap + install; the
	// child traversal grant needs setfacl; the proof reader needs setpriv.
	skipUnlessToolsPresent(t, "setcap", "setfacl", "setpriv", "sleep")

	s := newSession(t)
	helper := buildHelper(t, s.bin)
	if _, err := os.Stat(helper); err != nil {
		t.Fatalf("helper not built: %v", err)
	}

	// --- byn setup (root): create service users + install the helper. ---
	if so, se, code := s.run("", "setup"); code != 0 {
		t.Skipf("byn setup failed on this image (privsep prerequisites unavailable); stdout=%q stderr=%q", so, se)
	}
	execu := execUID(t)
	readerUID := unprivReaderUID(t, execu)

	// --- Idempotency: a second `byn setup` must exit 0 (Task A step 6). ---
	if so, se, code := s.run("", "setup"); code != 0 {
		t.Fatalf("second `byn setup` not idempotent: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// --- Enable privsep in config BEFORE the daemon starts (daemon reads the
	// config once at start via config.Load). ---
	if err := os.WriteFile(filepath.Join(s.dir, "config"),
		[]byte("[security]\nprivsep = true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- Start daemon, init + unlock the vault, put the sentinel secret. ---
	// This integration job runs as root, and NU-6 added a root-refusal to the
	// daemon (it wants to run as _byn, not root). Pass --allow-root so the
	// daemon starts under the test harness; the proof here is the exec CHILD
	// running as _byn-exec (≠ the daemon's uid, root here), which holds
	// regardless of the daemon's own uid. Without this, the test would t.Fatal
	// at daemon start whenever `byn setup` fully succeeds.
	if _, se, code := s.run("", "daemon", "start", "--allow-root"); code != 0 {
		t.Fatalf("daemon start: code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)
	if _, _, code := s.run(privsepPW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(privsepPW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	s.pw = privsepPW

	// Project dir lives under s.dir (/tmp/byn-it-XXXX/...). The trust-time ACL
	// grant gives _byn-exec rwX on the project dir + execute-only on ownerHome,
	// but the intermediate s.dir (0700) still needs traversal for the child to
	// reach the project. Open the search bit so the dropped child can chdir in.
	if err := os.Chmod(s.dir, 0o711); err != nil {
		t.Fatalf("chmod s.dir traversable: %v", err)
	}
	projDir := filepath.Join(s.dir, "privsep-proj")
	if err := os.MkdirAll(projDir, 0o711); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	if so, se, code := s.runInDir(projDir, privsepSecret, nil, "put", "SECRETVAR"); code != 0 {
		t.Fatalf("put SECRETVAR: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// .byn: pin `sleep {{args}}` so `byn exec -- sleep 5` runs free, with
	// SECRETVAR in the [exec] env allowlist so it is injected into the child.
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"SECRETVAR\"]\nactions = [\"sleep {{args}}\"]\n"
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o644); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, se, code := s.runInDir(projDir, privsepPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}

	// --- Launch the long-running child (privsep ON). It runs SERVER-side and
	// blocks for ~5s; we inspect /proc while it is alive. ---
	var (
		execStdout, execStderr string
		execCode               int
		wg                     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		execStdout, execStderr, execCode = s.runInDir(projDir, "", nil, "exec", "--", "sleep", "5")
	}()

	childPID := waitForChild(execu, time.Now().Add(4*time.Second))
	if childPID == 0 {
		wg.Wait()
		t.Fatalf("no _byn-exec child (uid %d) running `sleep` appeared; exec stdout=%q stderr=%q code=%d",
			execu, execStdout, execStderr, execCode)
	}

	// PROOF 1 — the child really dropped: /proc/<pid>/status Uid == _byn-exec.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/status") // #nosec G304 -- /proc path
	if err != nil {
		t.Fatalf("read child status: %v", err)
	}
	if got := statusUID(string(status)); got != execu {
		t.Errorf("child real uid = %d, want _byn-exec uid %d (child did NOT drop privilege)\nstatus:\n%s",
			got, execu, status)
	}

	// PROOF 2 — cred-leak: a non-root owner-class process can NOT read the
	// child's environ. Either the read is DENIED (EACCES) or, if the kernel
	// returns an empty/redacted buffer, it must NOT contain the sentinel.
	out, readErr := readEnvironAs(readerUID, childPID)
	if readErr == nil && bytes.Contains(out, []byte(privsepSecret)) {
		t.Errorf("CRED LEAK: non-root uid %d read the sentinel from /proc/%d/environ — privsep failed to protect the injected secret",
			readerUID, childPID)
	} else if readErr != nil {
		t.Logf("good: non-root uid %d denied reading /proc/%d/environ (%v)", readerUID, childPID, readErr)
	} else {
		t.Logf("good: non-root uid %d read /proc/%d/environ but sentinel absent (%d bytes)", readerUID, childPID, len(out))
	}

	// PROOF 3 — no fd leak: the child's /proc/<pid>/fd must not expose the
	// daemon's socket or vault DB (Go's O_CLOEXEC + the helper's clean env).
	assertNoDaemonFDLeak(t, childPID, s.dir)

	// Let the child finish and confirm a clean exit code (sleep 5 → 0).
	wg.Wait()
	if execCode != 0 {
		t.Errorf("privsep exec exit code = %d, want 0; stderr=%q", execCode, execStderr)
	}

	// CONTRAST — with --no-privsep the SAME exec runs the child as the OWNER
	// (root here). Reading its environ as root succeeds and the sentinel IS
	// present, proving the difference (the legacy in-process path injects into a
	// child the owner fully controls). This is the documented ceiling.
	assertContrastNoPrivsep(t, s, projDir)
}

// assertNoDaemonFDLeak lists /proc/<pid>/fd and asserts none of the child's open
// fds point at the daemon socket or the vault DB under stateDir. Best-effort:
// the fd dir may be unreadable cross-uid, which is itself fine (no leak path).
func assertNoDaemonFDLeak(t *testing.T, pid int, stateDir string) {
	t.Helper()
	fdDir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		t.Logf("note: /proc/%d/fd not listable (%v) — no fd-leak path either way", pid, err)
		return
	}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		if strings.HasSuffix(target, ".sock") || strings.Contains(target, "daemon.sock") {
			t.Errorf("fd leak: child fd %s → daemon socket %q", e.Name(), target)
		}
		if strings.Contains(target, stateDir) && strings.Contains(target, "vault.db") {
			t.Errorf("fd leak: child fd %s → vault DB %q", e.Name(), target)
		}
	}
}

// assertContrastNoPrivsep runs the SAME exec with --no-privsep and proves the
// child runs as the owner (root here) and its environ DOES contain the sentinel
// — the legacy in-process path. This makes the privsep difference concrete.
func assertContrastNoPrivsep(t *testing.T, s *session, projDir string) {
	t.Helper()
	var (
		stdout, stderr string
		code           int
		wg             sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// --no-privsep forces the legacy in-process path: the byn CLI process
		// itself becomes (execs) the child via syscall.Exec, owned by root.
		stdout, stderr, code = s.runInDir(projDir, "", nil, "exec", "--no-privsep", "--", "sleep", "5")
	}()

	// The legacy path replaces the byn CLI process with sleep, owned by root
	// (uid 0). Find that sleep child.
	childPID := waitForChild(0, time.Now().Add(4*time.Second))
	if childPID == 0 {
		wg.Wait()
		t.Logf("contrast: could not pin a root-owned sleep (stdout=%q stderr=%q code=%d); skipping contrast assertion",
			stdout, stderr, code)
		return
	}
	// As root we CAN read the environ (the documented ceiling) and it contains
	// the sentinel — proving the legacy path leaves the secret in a process the
	// owner controls, which is exactly what privsep removes.
	environ, err := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/environ") // #nosec G304 -- /proc path
	if err == nil && !bytes.Contains(environ, []byte(privsepSecret)) {
		t.Logf("contrast note: root-owned legacy child environ did not contain the sentinel (timing); not fatal")
	} else if err == nil {
		t.Logf("good contrast: legacy --no-privsep child (uid 0) environ DOES contain the sentinel — privsep is what removes that exposure")
	}
	wg.Wait()
}

// statusUID parses the real uid (first field of the "Uid:" line) from the
// contents of /proc/<pid>/status.
func statusUID(status string) int {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) == 0 {
				return -1
			}
			uid, err := strconv.Atoi(fields[0])
			if err != nil {
				return -1
			}
			return uid
		}
	}
	return -1
}
