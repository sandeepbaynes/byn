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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/byn")
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
}

func newSession(t *testing.T) *session {
	t.Helper()
	return &session{t: t, bin: binPath(t), dir: shortDir(t)}
}

// run executes one invocation of the byn binary. Returns stdout,
// stderr, exit code.
func (s *session) run(stdin string, args ...string) (string, string, int) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Env = append(os.Environ(), "BYN_DIR="+s.dir)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
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

func (s *session) stopDaemon() {
	s.t.Helper()
	_, _, _ = s.run("", "daemon", "stop")
}

// TestE2E_GoldenPath exercises init → unlock → put → get → lock → get-while-locked.
func TestE2E_GoldenPath(t *testing.T) {
	s := newSession(t)

	// Daemon down: status should exit 2 with recovery message.
	_, stderr, code := s.run("", "daemon", "status")
	if code != 2 {
		t.Fatalf("daemon down status: code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "daemon is not running") || !strings.Contains(stderr, "byn daemon start") {
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
	if _, _, code := s.run("s3cr3t-value", "put", "k"); code != 0 {
		t.Fatalf("put exited %d", code)
	}
	stdout, _ = s.mustRun("", "get", "k")
	if stdout != "s3cr3t-value" {
		t.Fatalf("get value = %q, want %q", stdout, "s3cr3t-value")
	}

	// List shows the key.
	stdout, _ = s.mustRun("", "list")
	if !strings.Contains(stdout, "k\n") && stdout != "k\n" && !strings.HasPrefix(stdout, "k") {
		t.Fatalf("list missing 'k':\n%s", stdout)
	}

	// Lock; subsequent Get fails with code 3.
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
	stdout, _ = s.mustRun("", "get", "k")
	if stdout != "s3cr3t-value" {
		t.Fatalf("post-relock get value = %q, want %q", stdout, "s3cr3t-value")
	}

	// Delete.
	if _, _, code := s.run("", "delete", "k"); code != 0 {
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
	_ = fmt.Sprintf("ok") // silence unused import in tidied versions
}

// TestE2E_Exec_InjectsEnvVars exercises the core injection path:
//   - daemon up, vault unlocked, two env-var entries stored
//   - `byn exec -- env` shows both vars in the child's environ
//   - parent shell env never had them
//   - exit code propagates from the child
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

	// Child is /usr/bin/env (POSIX-standard, always present on
	// Unix). Its stdout is the inherited environ.
	stdout, _, code := s.run("", "exec", "--", "env")
	if code != 0 {
		t.Fatalf("exec env exited %d\nstdout:\n%s", code, stdout)
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
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	const pw = "exec-test-password"
	_, _, _ = s.run(pw, "init", "--password-stdin")
	_, _, _ = s.run(pw, "unlock", "--password-stdin")

	// Child exits 7; exec replaces the byn CLI process, so the
	// shell sees 7 as the exit code of the whole invocation.
	_, _, code := s.run("", "exec", "--", "bash", "-c", "exit 7")
	if code != 7 {
		t.Fatalf("exec exit code = %d, want 7", code)
	}
}

func TestE2E_Exec_StoredOverridesParent(t *testing.T) {
	// When a stored entry has the same name as a var already in the
	// parent shell, the stored value wins (last-value-wins per POSIX,
	// which is what most shells/libraries follow).
	s := newSession(t)
	_, _ = s.mustRun("", "daemon", "start")
	t.Cleanup(s.stopDaemon)

	const pw = "exec-test-password"
	_, _, _ = s.run(pw, "init", "--password-stdin")
	_, _, _ = s.run(pw, "unlock", "--password-stdin")
	_, _, _ = s.run("stored-value", "put", "OVERRIDE_ME")

	// Run with OVERRIDE_ME=parent-value in byn's environment.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.bin, "exec", "--", "bash", "-c", "echo OVERRIDE_ME=$OVERRIDE_ME")
	cmd.Env = append(os.Environ(),
		"BYN_DIR="+s.dir,
		"OVERRIDE_ME=parent-value")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := strings.TrimSpace(stdout.String())
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
