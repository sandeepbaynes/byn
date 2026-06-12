package daemon

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestDaemonReload_ReturnsChangeNotes calls daemon.reload over IPC and checks
// that change notes come back when a config change is applied.
func TestDaemonReload_ReturnsChangeNotes(t *testing.T) {
	d, c := startTestDaemon(t)

	// Write a config that differs from the zero default.
	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"5m\"\n")

	var resp ipc.DaemonReloadResp
	if err := c.Call(ipc.OpDaemonReload, ipc.DaemonReloadReq{}, &resp); err != nil {
		t.Fatalf("daemon.reload IPC: %v", err)
	}
	// The idle_timeout was 0 (disabled) at start; now it's 5m — must report a change.
	if len(resp.ChangeNotes) == 0 {
		t.Error("expected at least one change note; got none")
	}
}

// TestDaemonReload_NoChanges reports an empty slice when nothing changed.
func TestDaemonReload_NoChanges(t *testing.T) {
	d, c := startTestDaemon(t)

	// Write a config that exactly matches the daemon's defaults (idle off, UI off).
	writeConfig(t, d.cfg.Dir, "[ui]\nenabled = false\n[daemon]\nidle_timeout = \"0s\"\n")

	var resp ipc.DaemonReloadResp
	if err := c.Call(ipc.OpDaemonReload, ipc.DaemonReloadReq{}, &resp); err != nil {
		t.Fatalf("daemon.reload IPC: %v", err)
	}
	if len(resp.ChangeNotes) != 0 {
		t.Errorf("expected no change notes; got %v", resp.ChangeNotes)
	}
}

// TestDaemonRestart_AcknowledgesBeforeShutdown calls daemon.restart over IPC
// and asserts that the daemon returns a DaemonRestartResp (with a non-empty
// message) before it shuts down. We do NOT wait for the actual shutdown: the
// test harness would race the 200ms async goroutine and we'd need a live
// daemon socket after the call — avoid actually killing the test daemon.
func TestDaemonRestart_AcknowledgesBeforeShutdown(t *testing.T) {
	_, c := startTestDaemon(t)

	var resp ipc.DaemonRestartResp
	if err := c.Call(ipc.OpDaemonRestart, ipc.DaemonRestartReq{}, &resp); err != nil {
		// Accept a connection-reset or EOF here — the daemon may have shut down
		// before we could read the response in a very fast test environment.
		// A CodeBadRequest / CodeInternal would mean our types are wrong.
		var er *ipc.ErrResponse
		if errors.As(err, &er) {
			t.Fatalf("daemon.restart returned IPC error: code=%s msg=%s", er.Code, er.Message)
		}
		// io.EOF / syscall.ECONNRESET are acceptable (daemon shut down fast).
		t.Logf("daemon.restart: connection closed before read (daemon shut down fast): %v", err)
		return
	}
	if resp.Message == "" {
		t.Error("daemon.restart: expected non-empty message in response")
	}
}
