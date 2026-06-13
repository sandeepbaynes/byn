//go:build integration

// Package integration drives the real byn binary end-to-end:
// build it, start the daemon, exercise CLI commands, verify state.
//
// Slow by construction (each Init runs Argon2id); kept out of the
// default `make test` and gated behind the integration build tag.
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// binPath builds the byn binary once per test run into a tempdir
// and returns its path.
func binPath(t *testing.T) string {
	t.Helper()
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "byn")
	// Build with -tags byntest so the execed binary honors BYN_TEST_DIR (the
	// test-only data-root seam that replaced the removed data-root override).
	cmd := exec.Command("go", "build", "-tags", "byntest", "-o", bin, "./cmd/byn")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// We're at <repo>/tests/integration/e2e_test.go. Walk up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

// shortDir creates a short path under /tmp (Unix socket name length
// is capped at 104 chars on macOS; t.TempDir() returns paths around
// 100 chars).
func shortDir(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := filepath.Join("/tmp", "byn-it-"+hex.EncodeToString(b[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type session struct {
	t   *testing.T
	bin string
	dir string
	// pw is the vault master password stored at bootstrap time.
	// Non-TTY integration tests have no session file (ttyRdev()==0 ⇒ no session
	// is written by byn unlock).  Auth-gated CLI calls must supply the password
	// explicitly via --password-stdin; pw is the credential for those calls.
	pw string
}

func newSession(t *testing.T) *session {
	t.Helper()
	s := &session{t: t, bin: binPath(t), dir: shortDir(t)}
	// Auto-reap this session's daemon at test end, even if the test forgot to
	// register cleanup. stopDaemon force-kills a daemon that survives `stop`,
	// so a flaky shutdown can never leak processes across the many runs.
	t.Cleanup(s.stopDaemon)
	return s
}

// run executes one invocation of the byn binary. Returns stdout,
// stderr, exit code.
func (s *session) run(stdin string, args ...string) (string, string, int) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Env = append(os.Environ(), "BYN_TEST_DIR="+s.dir)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		// Explicitly redirect stdin from /dev/null so the child process does not
		// inherit the test runner's TTY. Without this, byn sees a TTY on stdin and
		// attempts an interactive password prompt — which then fails with "not a
		// terminal" when the test binary's stdin is a character device but not
		// configured for raw-mode input (typical when run under `go test`).
		cmd.Stdin = strings.NewReader("")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			s.t.Fatalf("run %v: %v", args, err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func (s *session) mustRun(stdin string, args ...string) (string, string) {
	s.t.Helper()
	stdout, stderr, code := s.run(stdin, args...)
	if code != 0 {
		s.t.Fatalf("byn %v exited %d\nstdout: %s\nstderr: %s", args, code, stdout, stderr)
	}
	return stdout, stderr
}

// runPW runs a byn command, prepending s.pw+"\n" to stdin.
// Use for auth-gated operations (get --password-stdin, delete --password-stdin,
// export --password-stdin, etc.) where the caller supplies --password-stdin in
// the args and just needs the password injected as stdin.
//
// Non-TTY integration tests have no session file (ttyRdev()==0 ⇒ byn unlock
// does not write a session); per-action credentials via --password-stdin are
// the documented agent workflow.
func (s *session) runPW(extraStdin string, args ...string) (string, string, int) {
	s.t.Helper()
	if s.pw == "" {
		s.t.Fatal("runPW: s.pw is empty — set s.pw (e.g. via bootstrapUnlocked) before using runPW")
	}
	return s.run(s.pw+"\n"+extraStdin, args...)
}

// mustRunPW is runPW that fatals on non-zero exit.
func (s *session) mustRunPW(extraStdin string, args ...string) (string, string) {
	s.t.Helper()
	stdout, stderr, code := s.runPW(extraStdin, args...)
	if code != 0 {
		s.t.Fatalf("byn %v exited %d\nstdout: %s\nstderr: %s", args, code, stdout, stderr)
	}
	return stdout, stderr
}

// runPWInDir is runPW but runs in a specific working directory.
func (s *session) runPWInDir(cwd string, extraEnv []string, args ...string) (string, string, int) {
	s.t.Helper()
	if s.pw == "" {
		s.t.Fatal("runPWInDir: s.pw is empty")
	}
	return s.runInDir(cwd, s.pw+"\n", extraEnv, args...)
}

func (s *session) stopDaemon() {
	s.t.Helper()
	pid := s.daemonPID() // capture before stop — a clean stop removes the pidfile
	_, _, _ = s.run("", "daemon", "stop")
	if pid <= 0 {
		return
	}
	// Guarantee the process is gone. A flaky `daemon stop` must never leave a
	// stray daemon holding socket + WAL FDs — across many integration runs that
	// is exactly what exhausts the system file table.
	for i := 0; i < 100; i++ { // up to ~2s
		if syscall.Kill(pid, 0) != nil { // ESRCH → already gone
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	s.t.Errorf("daemon (pid %d) survived `daemon stop` for 2s — force-killed; investigate shutdown", pid)
}

// daemonPID reads this session's daemon pidfile (in the data dir), or 0 when
// absent/unreadable. Used by stopDaemon to verify the process actually died.
func (s *session) daemonPID() int {
	b, err := os.ReadFile(filepath.Join(s.dir, "daemon.pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// TestE2E_GoldenPath exercises init → unlock → put → get → lock → get-while-locked.
func TestE2E_GoldenPath(t *testing.T) {
	s := newSession(t)

	// Daemon down: status should exit 2 with recovery message.
	_, stderr, code := s.run("", "daemon", "status")
	if code != 2 {
		t.Fatalf("daemon down status: code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "daemon is not running") || !strings.Contains(stderr, "byn start") {
		t.Fatalf("daemon down stderr missing recovery message:\n%s", stderr)
	}

	// Start daemon (detached).
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	// Status: not initialized yet.
	stdout, _ := s.mustRun("", "daemon", "status")
	// v2 status output: "vaults:  (none initialized)" when no
	// vault has been created yet.
	if !strings.Contains(stdout, "none initialized") {
		t.Fatalf("status before init missing 'none initialized':\n%s", stdout)
	}

	pw := "correct-horse-battery-staple"

	// Init.
	if _, _, code := s.run(pw, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init exited %d", code)
	}

	// Status: initialized, locked.
	stdout, _ = s.mustRun("", "status")
	if !strings.Contains(stdout, "locked") || strings.Contains(stdout, "unlocked") {
		t.Fatalf("post-init status not 'locked':\n%s", stdout)
	}

	// Put while locked → fails.
	_, stderr, code = s.run("v", "put", "k")
	if code != exitDaemonErrCode {
		t.Fatalf("put while locked: code = %d, want %d\nstderr: %s", code, exitDaemonErrCode, stderr)
	}

	// Unlock.
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock exited %d", code)
	}

	// Put then Get.
	// Insert (new name) is free; get/delete need --password-stdin in non-TTY
	// context (ttyRdev()==0 ⇒ no session file is written by byn unlock; agent
	// workflow is per-action credentials via --password-stdin).
	s.pw = pw
	if _, _, code := s.run("s3cr3t-value", "put", "k"); code != 0 {
		t.Fatalf("put exited %d", code)
	}
	stdout, _ = s.mustRunPW("", "get", "--password-stdin", "k")
	if stdout != "s3cr3t-value" {
		t.Fatalf("get value = %q, want %q", stdout, "s3cr3t-value")
	}

	// List shows the key (list is free — no session or password needed).
	stdout, _ = s.mustRun("", "list")
	if !strings.Contains(stdout, "k\n") && stdout != "k\n" && !strings.HasPrefix(stdout, "k") {
		t.Fatalf("list missing 'k':\n%s", stdout)
	}

	// Lock; subsequent Get fails with code 3 (vault locked, no session).
	if _, _, code := s.run("", "lock"); code != 0 {
		t.Fatalf("lock exited %d", code)
	}
	_, _, code = s.run("", "get", "k")
	if code != exitDaemonErrCode {
		t.Fatalf("get after lock: code = %d, want %d", code, exitDaemonErrCode)
	}

	// Re-unlock and confirm value is still there.
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("re-unlock exited %d", code)
	}
	stdout, _ = s.mustRunPW("", "get", "--password-stdin", "k")
	if stdout != "s3cr3t-value" {
		t.Fatalf("post-relock get value = %q, want %q", stdout, "s3cr3t-value")
	}

	// Delete — needs --password-stdin in non-TTY context.
	if _, _, code := s.runPW("", "delete", "--password-stdin", "k"); code != 0 {
		t.Fatalf("delete exited %d", code)
	}
	_, _, code = s.run("", "get", "k")
	if code != exitDaemonErrCode {
		t.Fatalf("get after delete: code = %d, want %d", code, exitDaemonErrCode)
	}
}

// Mirror of common.exitDaemonErr from the CLI package (not exported).
const exitDaemonErrCode = 3

// TestE2E_StatusOnly verifies the daemon lifecycle + status flow,
// which doesn't require password prompts.
func TestE2E_StatusOnly(t *testing.T) {
	s := newSession(t)

	// Status with no daemon → exit 2.
	_, _, code := s.run("", "daemon", "status")
	if code != 2 {
		t.Fatalf("no-daemon status: code = %d, want 2", code)
	}

	// Start the daemon.
	stdout, stderr := s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)
	if !strings.Contains(stderr, "daemon started") {
		t.Fatalf("start stderr missing 'daemon started':\nstdout=%s\nstderr=%s", stdout, stderr)
	}

	// Status now succeeds and reports no vaults yet.
	stdout, _ = s.mustRun("", "daemon", "status")
	for _, want := range []string{"running", "none initialized"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("status missing %q:\n%s", want, stdout)
		}
	}

	// `status` (no `daemon`) is an alias.
	stdout2, _ := s.mustRun("", "status")
	if !strings.Contains(stdout2, "running") {
		t.Fatalf("alias status missing 'running':\n%s", stdout2)
	}

	// Double-start: detect already running.
	stdout3, stderr3, code3 := s.run("", "daemon", "start")
	if code3 != 0 {
		t.Fatalf("second start exited %d (expected 0 with 'already running' note)\nstdout=%s\nstderr=%s",
			code3, stdout3, stderr3)
	}
	if !strings.Contains(stderr3, "already running") {
		t.Fatalf("second start stderr missing 'already running':\n%s", stderr3)
	}

	// Stop the daemon.
	_, stopStderr, code := s.run("", "daemon", "stop")
	if code != 0 {
		t.Fatalf("stop exited %d: %s", code, stopStderr)
	}
	if !strings.Contains(stopStderr, "stopped") {
		t.Fatalf("stop stderr missing 'stopped':\n%s", stopStderr)
	}

	// Socket should be gone.
	sockPath := filepath.Join(s.dir, "daemon.sock")
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket still present after stop: %v", err)
	}
}

func TestE2E_UnknownCommand(t *testing.T) {
	s := newSession(t)
	stdout, stderr, code := s.run("", "bogus")
	if code != 1 {
		t.Fatalf("unknown command: code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Fatalf("stderr missing 'unknown command':\n%s\nstdout: %s", stderr, stdout)
	}
}

// TestE2E_VersionStable verifies `byn version` doesn't accidentally
// require a daemon and prints something parseable.
func TestE2E_VersionStable(t *testing.T) {
	s := newSession(t)
	stdout, _, code := s.run("", "version")
	if code != 0 {
		t.Fatalf("version exited %d", code)
	}
	if !strings.HasPrefix(stdout, "byn ") {
		t.Fatalf("version stdout = %q, want byn prefix", stdout)
	}
}

// dummy is a sanity check that the test harness builds + can call the
// binary at all. Useful when triaging.
func TestE2E_HarnessSelfCheck(t *testing.T) {
	s := newSession(t)
	stdout, _, code := s.run("", "help")
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}
	if !strings.Contains(stdout, "Usage:") {
		t.Fatalf("help stdout missing 'Usage:':\n%s", stdout)
	}
}

// TestE2E_Exec_InjectsEnvVars exercises the core injection path:
//   - daemon up, vault unlocked, two env-var entries stored
//   - `byn exec -- env` (via a trusted .byn) shows both vars in the child's environ
//   - parent shell env never had them
//
// NU-3: ad-hoc exec requires fresh credentials; the test uses a trusted .byn
// with /usr/bin/env pinned in [exec] actions so exec runs credential-free.
func TestE2E_Exec_InjectsEnvVars(t *testing.T) {
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	const pw = "exec-test-password"
	if _, _, code := s.run(pw, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init exited %d", code)
	}
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock exited %d", code)
	}
	if _, _, code := s.run("db-secret-value", "put", "DB_URL"); code != 0 {
		t.Fatalf("put DB_URL exited %d", code)
	}
	if _, _, code := s.run("api-token-value", "put", "API_TOKEN"); code != 0 {
		t.Fatalf("put API_TOKEN exited %d", code)
	}

	// Set up a trusted .byn that pins /usr/bin/env in [exec] actions and
	// allows both vars in [exec] env.  This satisfies the NU-3 auth gate for
	// exec without requiring fresh credentials on every invocation.
	projDir := filepath.Join(s.dir, "exec-inject-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	bynContent := "[scope]\nproject = \"default\"\n[exec]\nenv = [\"DB_URL\", \"API_TOKEN\"]\nactions = [\"/usr/bin/env\"]\n"
	if err := os.WriteFile(filepath.Join(projDir, ".byn"), []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, se, code := s.runInDir(projDir, pw+"\n", nil, "trust", "--password-stdin", filepath.Join(projDir, ".byn")); code != 0 {
		t.Fatalf("trust .byn: code=%d stderr=%q", code, se)
	}

	// Child is /usr/bin/env (POSIX-standard, always present on Unix).
	// Its stdout is the inherited environ + injected vars.
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/usr/bin/env")
	if code != 0 {
		t.Fatalf("exec env exited %d\nstderr: %s\nstdout:\n%s", code, se, stdout)
	}
	if !strings.Contains(stdout, "DB_URL=db-secret-value") {
		t.Fatalf("child env missing DB_URL=db-secret-value:\n%s", stdout)
	}
	if !strings.Contains(stdout, "API_TOKEN=api-token-value") {
		t.Fatalf("child env missing API_TOKEN=api-token-value:\n%s", stdout)
	}
}

func TestE2E_Exec_RequiresSeparator(t *testing.T) {
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	_, stderr, code := s.run("", "exec")
	if code == 0 {
		t.Fatal("exec without `--` exited 0; want failure")
	}
	if !strings.Contains(stderr, "--") {
		t.Fatalf("stderr missing usage mention of `--`:\n%s", stderr)
	}
}

func TestE2E_Exec_PropagatesExitCode(t *testing.T) {
	// NU-3: ad-hoc exec requires fresh credentials; use a trusted .byn with
	// /bin/bash {{args}} pinned so the exit-code-propagation test runs free.
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	const pw = "exec-test-password"
	if _, _, code := s.run(pw, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init exited %d", code)
	}
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock exited %d", code)
	}

	projDir := filepath.Join(s.dir, "exec-exit-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	// Pin "/bin/bash {{args}}" so any /bin/bash invocation (with any args) runs
	// free.  We use the absolute path to avoid PATH-resolution issues in the
	// restricted test env that runInDir sets up.
	bynContent := "[scope]\nproject = \"default\"\n[exec]\nenv = []\nactions = [\"/bin/bash {{args}}\"]\n"
	if err := os.WriteFile(filepath.Join(projDir, ".byn"), []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, se, code := s.runInDir(projDir, pw+"\n", nil, "trust", "--password-stdin", filepath.Join(projDir, ".byn")); code != 0 {
		t.Fatalf("trust .byn: code=%d stderr=%q", code, se)
	}

	// Child exits 7; exec replaces the byn CLI process, so the
	// shell sees 7 as the exit code of the whole invocation.
	_, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/bin/bash", "-c", "exit 7")
	if code != 7 {
		t.Fatalf("exec exit code = %d, want 7; stderr: %s", code, se)
	}
}

func TestE2E_Exec_StoredOverridesParent(t *testing.T) {
	// When a stored entry has the same name as a var already in the
	// parent shell, the stored value wins (last-value-wins per POSIX,
	// which is what most shells/libraries follow).
	//
	// NU-3: ad-hoc exec requires fresh credentials; use a trusted .byn with
	// /bin/bash {{args}} pinned so exec runs credential-free.
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	const pw = "exec-test-password"
	if _, _, code := s.run(pw, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init exited %d", code)
	}
	if _, _, code := s.run(pw, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock exited %d", code)
	}
	if _, _, code := s.run("stored-value", "put", "OVERRIDE_ME"); code != 0 {
		t.Fatalf("put OVERRIDE_ME exited %d", code)
	}

	projDir := filepath.Join(s.dir, "exec-override-proj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	// Use the absolute path to avoid PATH-resolution issues in the restricted
	// test env that runInDir sets up; pin /bin/bash so any invocation is free.
	bynContent := "[scope]\nproject = \"default\"\n[exec]\nenv = [\"OVERRIDE_ME\"]\nactions = [\"/bin/bash {{args}}\"]\n"
	if err := os.WriteFile(filepath.Join(projDir, ".byn"), []byte(bynContent), 0o600); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	if _, se, code := s.runInDir(projDir, pw+"\n", nil, "trust", "--password-stdin", filepath.Join(projDir, ".byn")); code != 0 {
		t.Fatalf("trust .byn: code=%d stderr=%q", code, se)
	}

	// Run with OVERRIDE_ME=parent-value in byn's environment via runInDir's
	// extra env parameter. The stored value must win over the parent env.
	stdout, se, code := s.runInDir(projDir, "", []string{"OVERRIDE_ME=parent-value"},
		"exec", "--", "/bin/bash", "-c", "echo OVERRIDE_ME=$OVERRIDE_ME")
	if code != 0 {
		t.Fatalf("exec exited %d; stderr: %s", code, se)
	}
	got := strings.TrimSpace(stdout)
	if got != "OVERRIDE_ME=stored-value" {
		t.Fatalf("override behaviour broke: got %q, want OVERRIDE_ME=stored-value", got)
	}
}

func TestE2E_Exec_HelpReachable(t *testing.T) {
	s := newSession(t)
	for _, args := range [][]string{
		{"exec", "help"},
		{"exec", "--help"},
		{"exec", "-h"},
		{"help", "exec"},
	} {
		stdout, _, code := s.run("", args...)
		if code != 0 {
			t.Errorf("`byn %s` exited %d", strings.Join(args, " "), code)
			continue
		}
		if !strings.Contains(stdout, "byn-exec") {
			t.Errorf("`byn %s` missing 'byn-exec' header:\n%s", strings.Join(args, " "), stdout)
		}
	}
}
