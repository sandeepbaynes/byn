package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunDaemon_NoSub(t *testing.T) {
	if got := runDaemon(nil); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemon_Unknown(t *testing.T) {
	if got := runDaemon([]string{"oops"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunStatus_DelegatesToDaemonStatus(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "test",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   time.Now().Add(-time.Hour),
		Vaults:      []ipc.VaultSummary{},
	})
	if got := runStatus(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStatus_VaultsListed(t *testing.T) {
	now := time.Now()
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   now.Add(-time.Hour),
		Vaults: []ipc.VaultSummary{
			{Name: "default", Initialized: true, Locked: false, LastActive: &now},
			{Name: "acme", Initialized: true, Locked: true},
		},
	})
	if got := runDaemonStatus(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStatus_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{StartedAt: time.Now()})
	if got := runDaemonStatus([]string{"--json"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStatus_BadFlag(t *testing.T) {
	if got := runDaemonStatus([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStatus_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runDaemonStatus(nil); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStop_NoPidFile(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if got := runDaemonStop(nil); got != exitOK {
		t.Fatalf("got %d (no pidfile should be exitOK)", got)
	}
}

func TestRunDaemonStop_BadPidContent(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if err := os.WriteFile(filepath.Join(td, daemon.PIDFilename), []byte("notanumber"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runDaemonStop(nil); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStop_BadFlag(t *testing.T) {
	if got := runDaemonStop([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStart_BadFlag(t *testing.T) {
	if got := runDaemonStart([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDaemonStart_DetachedTriggersAlreadyRunning(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	if got := runDaemonStart(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

// --allow-root is a recognized daemon-start flag (it threads into
// daemon.Config.AllowRoot). With a fake daemon already responding, start
// short-circuits to "already running" — proving the flag parses cleanly rather
// than erroring as unknown.
func TestRunDaemonStart_AllowRootFlagAccepted(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	if got := runDaemonStart([]string{"--allow-root"}); got != exitOK {
		t.Fatalf("got %d, want exitOK (flag accepted, daemon already running)", got)
	}
}

// ---- reload -------------------------------------------------------------

func TestRunDaemonReload_NotRunning(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if got := runDaemonReload(nil); got != exitErr {
		t.Fatalf("got %d, want exitErr (no daemon to reload)", got)
	}
}

func TestRunDaemonReload_BadPidContent(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if err := os.WriteFile(filepath.Join(td, daemon.PIDFilename), []byte("notanumber"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runDaemonReload(nil); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunDaemonReload_BadFlag(t *testing.T) {
	if got := runDaemonReload([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunDaemonReload_SendsSignal(t *testing.T) {
	// Catch SIGHUP so signalling our own PID doesn't terminate the test
	// (Go's default SIGHUP action is to exit).
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)

	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if err := os.WriteFile(filepath.Join(td, daemon.PIDFilename),
		[]byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runDaemonReload(nil); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("SIGHUP was not delivered")
	}
}

func TestRunDaemon_ReloadDispatch(t *testing.T) {
	// Routes through the daemon subcommand switch; bad flag fails before
	// any pidfile/socket access, so this never touches a real daemon.
	if got := runDaemon([]string{"reload", "--zzz"}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

// ---- restart ------------------------------------------------------------

func TestRunDaemonRestart_StopFailsAborts(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	// A malformed pidfile makes the stop leg fail, which must abort the
	// restart rather than fall through to start.
	if err := os.WriteFile(filepath.Join(td, daemon.PIDFilename), []byte("notanumber"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runDaemonRestart(nil); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunDaemonRestart_DegradesToStart(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	// Nothing running: stop is a no-op (exitOK) and restart forwards to
	// start, which here fails on the bad flag — proving the stop→start
	// handoff without spawning a real daemon.
	if got := runDaemonRestart([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunDaemon_RestartDispatch(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_TEST_DIR", td)
	if got := runDaemon([]string{"restart", "--zzz"}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestWaitForSocket_ReturnsTrueOnAvailable(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	if !waitForSocket(fd.dir, time.Second) {
		t.Fatal("expected true")
	}
}

func TestWaitForSocket_ReturnsFalseOnAbsent(t *testing.T) {
	dir := t.TempDir()
	if waitForSocket(dir, 200*time.Millisecond) {
		t.Fatal("expected false")
	}
}

// TestRunDaemonStatus_NoSessionSuffix asserts that an unlocked vault
// without an active session shows the dim "[no session in this terminal
// — byn unlock to authorize reads]" suffix and the footnote line.
func TestRunDaemonStatus_NoSessionSuffix(t *testing.T) {
	now := time.Now()
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   now.Add(-time.Hour),
		Vaults: []ipc.VaultSummary{
			{Name: "maison", Initialized: true, Locked: false, SessionActive: false},
		},
	})
	var rc int
	out := captureStdout(t, func() { rc = runDaemonStatus(nil) })
	if rc != exitOK {
		t.Fatalf("exit %d", rc)
	}
	if !strings.Contains(out, "no session in this terminal") {
		t.Errorf("expected no-session suffix; got:\n%s", out)
	}
	if !strings.Contains(out, `"unlocked" = the daemon holds the key`) {
		t.Errorf("expected footnote; got:\n%s", out)
	}
}

// TestRunDaemonStatus_SessionActiveSuffix asserts that an unlocked vault
// WITH an active session shows the "[session: active, expires in …]"
// suffix and does NOT show the no-session copy or footnote.
func TestRunDaemonStatus_SessionActiveSuffix(t *testing.T) {
	now := time.Now()
	exp := now.Add(15 * time.Minute)
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   now.Add(-time.Hour),
		Vaults: []ipc.VaultSummary{
			{Name: "default", Initialized: true, Locked: false, SessionActive: true, SessionExpiresAt: &exp},
		},
	})
	var rc int
	out := captureStdout(t, func() { rc = runDaemonStatus(nil) })
	if rc != exitOK {
		t.Fatalf("exit %d", rc)
	}
	if !strings.Contains(out, "session: active, expires in") {
		t.Errorf("expected active-session suffix; got:\n%s", out)
	}
	if strings.Contains(out, "no session in this terminal") {
		t.Errorf("unexpected no-session suffix; got:\n%s", out)
	}
	if strings.Contains(out, `"unlocked" = the daemon holds the key`) {
		t.Errorf("unexpected footnote when session is active; got:\n%s", out)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestRunDaemonStatus_FDAGranted asserts that "fda: granted" is printed
// when the daemon reports FDAGranted = true.
func TestRunDaemonStatus_FDAGranted(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   time.Now().Add(-time.Hour),
		Privsep:     true,
		FDAGranted:  boolPtr(true),
	})
	var rc int
	out := captureStdout(t, func() { rc = runDaemonStatus(nil) })
	if rc != exitOK {
		t.Fatalf("exit %d", rc)
	}
	if !strings.Contains(out, "fda:") {
		t.Errorf("expected fda: line; got:\n%s", out)
	}
	if !strings.Contains(out, "granted") {
		t.Errorf("expected 'granted'; got:\n%s", out)
	}
}

// TestRunDaemonStatus_FDANotGranted asserts that a warning is printed
// when the daemon reports FDAGranted = false.
func TestRunDaemonStatus_FDANotGranted(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   time.Now().Add(-time.Hour),
		Privsep:     true,
		FDAGranted:  boolPtr(false),
	})
	var rc int
	out := captureStdout(t, func() { rc = runDaemonStatus(nil) })
	if rc != exitOK {
		t.Fatalf("exit %d; status should remain 0 (non-fatal warning)", rc)
	}
	if !strings.Contains(out, "NOT GRANTED") {
		t.Errorf("expected NOT GRANTED warning; got:\n%s", out)
	}
	if !strings.Contains(out, "Full Disk Access") {
		t.Errorf("expected remediation hint; got:\n%s", out)
	}
}

// TestRunDaemonStatus_FDAAbsent asserts that no fda: line is printed
// when FDAGranted is nil (privsep off or non-macOS).
func TestRunDaemonStatus_FDAAbsent(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{
		Version:     "v",
		ProtocolMin: ipc.ProtocolMin,
		ProtocolMax: ipc.ProtocolVersion,
		StartedAt:   time.Now().Add(-time.Hour),
	})
	var rc int
	out := captureStdout(t, func() { rc = runDaemonStatus(nil) })
	if rc != exitOK {
		t.Fatalf("exit %d", rc)
	}
	if strings.Contains(out, "fda:") {
		t.Errorf("unexpected fda: line when FDAGranted is nil; got:\n%s", out)
	}
}
