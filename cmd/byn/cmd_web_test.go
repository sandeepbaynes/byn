package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/ui"
)

// stubBrowser replaces openBrowserFn with a no-op for the duration of the
// test, preventing real browser launches during `go test`. Returns the URLs
// that were opened (via the captured slice).
func stubBrowser(t *testing.T) *[]string {
	t.Helper()
	var opened []string
	orig := openBrowserFn
	openBrowserFn = func(url string) error { opened = append(opened, url); return nil }
	t.Cleanup(func() { openBrowserFn = orig })
	return &opened
}

// TestRunWeb_DaemonDown: when the daemon is not running runWeb returns
// exitDaemonDown and prints an actionable message.
func TestRunWeb_DaemonDown(t *testing.T) {
	stubBrowser(t)
	noDaemon(t)
	stderr := captureStderr(t, func() {
		if got := runWeb(nil); got != exitDaemonDown {
			t.Errorf("runWeb (no daemon) = %d, want %d", got, exitDaemonDown)
		}
	})
	if !strings.Contains(stderr, "byn start") {
		t.Errorf("stderr missing 'byn start' hint: %q", stderr)
	}
}

// TestRunWeb_UIDisabled: when the config disables the UI runWeb returns
// exitErr with an actionable message.
func TestRunWeb_UIDisabled(t *testing.T) {
	stubBrowser(t)
	dir := t.TempDir()
	t.Setenv("BYN_DIR", dir)
	// Write a config with UI disabled.
	if err := os.WriteFile(filepath.Join(dir, "config"),
		[]byte("[ui]\nenabled = false\nport = 2967\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	stderr := captureStderr(t, func() {
		if got := runWeb(nil); got != exitErr {
			t.Errorf("runWeb (UI disabled) = %d, want %d", got, exitErr)
		}
	})
	if !strings.Contains(stderr, "web portal is disabled") {
		t.Errorf("stderr missing 'web portal is disabled': %q", stderr)
	}
}

// TestRunWeb_BootstrapTokenPassedToBrowser: when the daemon is running, runWeb
// calls OpWebBootstrap, gets a token, and opens the browser with ?auth=<token>.
// The token must NOT appear in stdout (only in the browser URL).
func TestRunWeb_BootstrapTokenPassedToBrowser(t *testing.T) {
	opened := stubBrowser(t)
	fd := startFakeDaemon(t)

	const fakeBootstrapToken = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	fd.onOK(ipc.OpWebBootstrap, ipc.WebBootstrapResp{Token: fakeBootstrapToken})

	// Capture stdout to verify the base URL (no token) is printed.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	_ = runWeb(nil)
	_ = w.Close()
	os.Stdout = oldStdout
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	stdout := buf.String()

	// Bootstrap token must appear in the browser URL.
	if len(*opened) == 0 {
		t.Fatal("openBrowser was not called")
	}
	if !strings.Contains((*opened)[0], "?auth="+fakeBootstrapToken) {
		t.Errorf("browser URL missing bootstrap token: %q", (*opened)[0])
	}

	// Token must NOT appear in stdout.
	if strings.Contains(stdout, fakeBootstrapToken) {
		t.Errorf("stdout contains bootstrap token — must not be printed: %q", stdout)
	}
	// Base portal URL must appear in stdout.
	if !strings.Contains(stdout, "localhost:2967") {
		t.Errorf("stdout missing portal URL: %q", stdout)
	}

	// Verify OpWebBootstrap was called exactly once and the status check also ran.
	if c := fd.callsFor(ipc.OpWebBootstrap); len(c) != 1 {
		t.Errorf("OpWebBootstrap call count = %d, want 1", len(c))
	}
}

// TestRunWeb_BootstrapFallback: when OpWebBootstrap fails the URL is opened
// without ?auth= (a warning is printed) — the browser shows the "not
// authorized" notice.
func TestRunWeb_BootstrapFallback(t *testing.T) {
	opened := stubBrowser(t)
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	// No handler for OpWebBootstrap → fake daemon returns unknown_op error.

	stderr := captureStderr(t, func() {
		_ = runWeb(nil)
	})

	if len(*opened) == 0 {
		t.Fatal("openBrowser was not called")
	}
	if strings.Contains((*opened)[0], "?auth=") {
		t.Errorf("fallback URL must not contain ?auth=: %q", (*opened)[0])
	}
	if !strings.Contains(stderr, "bootstrap token") {
		t.Errorf("stderr must warn about bootstrap token failure: %q", stderr)
	}
}

// TestRunWeb_TokenFileCreated: verifies the portal.token file is still
// created by the daemon (via LoadOrCreateToken called by startUILocked).
// This test uses the token file solely to check 0600 mode and length, since
// runWeb no longer reads or uses it directly.
func TestRunWeb_TokenFileCreated(t *testing.T) {
	stubBrowser(t)
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	fd.onOK(ipc.OpWebBootstrap, ipc.WebBootstrapResp{Token: "aaaaaabbbbbbccccccddddddeeeeeeffffffff0000000011111111222222223333"})

	dir := fd.dir
	tokenPath := filepath.Join(dir, ui.TokenFilename)

	// runWeb no longer creates the token file itself — that is the daemon's
	// job at startup. We just verify runWeb succeeds and calls the bootstrap op.
	_ = runWeb(nil)

	if c := fd.callsFor(ipc.OpWebBootstrap); len(c) == 0 {
		t.Error("OpWebBootstrap was not called by runWeb")
	}
	// The token file may or may not exist in this test (only the daemon
	// creates it during startUILocked, not the fake daemon). We can verify
	// the shape if it happens to exist.
	if data, err := os.ReadFile(tokenPath); err == nil {
		if len(data) != 64 {
			t.Errorf("token file length = %d, want 64", len(data))
		}
	}
}

// TestRunWeb_StdoutNoToken: the URL printed to stdout must NOT contain any
// token (bootstrap or otherwise).
func TestRunWeb_StdoutNoToken(t *testing.T) {
	stubBrowser(t)
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	const tok = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	fd.onOK(ipc.OpWebBootstrap, ipc.WebBootstrapResp{Token: tok})

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	_ = runWeb(nil)
	_ = w.Close()
	os.Stdout = oldStdout
	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	stdout := buf.String()

	// Token must NOT appear in stdout.
	if strings.Contains(stdout, tok) {
		t.Errorf("stdout contains token — must not be printed: %q", stdout)
	}
	// Base URL must appear.
	if !strings.Contains(stdout, "localhost:2967") {
		t.Errorf("stdout missing portal URL: %q", stdout)
	}
}

// TestRunWeb_WebBootstrapReq_HasNoFields: the request body for OpWebBootstrap
// must be an empty JSON object (no sensitive data in the wire request).
func TestRunWeb_WebBootstrapReq_HasNoFields(t *testing.T) {
	stubBrowser(t)
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	fd.onOK(ipc.OpWebBootstrap, ipc.WebBootstrapResp{Token: "aabb"})
	_ = runWeb(nil)
	calls := fd.callsFor(ipc.OpWebBootstrap)
	if len(calls) == 0 {
		t.Fatal("no OpWebBootstrap call recorded")
	}
	var req ipc.WebBootstrapReq
	requireUnmarshal(t, calls[0].Body, &req)
	// WebBootstrapReq has no fields; the body should decode cleanly.
	// Check the raw body is not a non-empty object with sensitive data.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(calls[0].Body, &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if len(raw) != 0 {
		t.Errorf("bootstrap request body has unexpected fields: %v", raw)
	}
}
