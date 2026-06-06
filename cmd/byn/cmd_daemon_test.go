package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	t.Setenv("BYN_DIR", td)
	if got := runDaemonStop(nil); got != exitOK {
		t.Fatalf("got %d (no pidfile should be exitOK)", got)
	}
}

func TestRunDaemonStop_BadPidContent(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
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

// ---- reload -------------------------------------------------------------

func TestRunDaemonReload_NotRunning(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
	if got := runDaemonReload(nil); got != exitErr {
		t.Fatalf("got %d, want exitErr (no daemon to reload)", got)
	}
}

func TestRunDaemonReload_BadPidContent(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
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
	t.Setenv("BYN_DIR", td)
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
	t.Setenv("BYN_DIR", td)
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
	t.Setenv("BYN_DIR", td)
	// Nothing running: stop is a no-op (exitOK) and restart forwards to
	// start, which here fails on the bad flag — proving the stop→start
	// handoff without spawning a real daemon.
	if got := runDaemonRestart([]string{"--zzz"}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunDaemon_RestartDispatch(t *testing.T) {
	td := t.TempDir()
	t.Setenv("BYN_DIR", td)
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
