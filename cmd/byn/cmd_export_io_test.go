package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// register simulates the daemon-side fan-out: list returns one secret,
// and get returns its bytes.
func registerListGet(fd *fakeDaemon, entries map[string]string) {
	metas := make([]ipc.SecretMeta, 0, len(entries))
	for k := range entries {
		metas = append(metas, ipc.SecretMeta{Name: k})
	}
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: metas})
	fd.on(ipc.OpGet, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.GetReq
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, &ipc.ErrMsg{Code: ipc.CodeInternal, Message: err.Error()}
		}
		v, ok := entries[req.Name]
		if !ok {
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotFound, Message: "no"}
		}
		return ipc.GetResp{Name: req.Name, Value: []byte(v)}, nil
	})
}

func TestRunExport_DotenvToStdout(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1", "B": "two"})
	if got := runExport(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1"})
	if got := runExport([]string{"--format=json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_YAML(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1"})
	if got := runExport([]string{"--format=yaml"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_UnsupportedFormat(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1"})
	if got := runExport([]string{"--format=xml"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_OutputFile(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1"})
	out := filepath.Join(t.TempDir(), "x.env")
	if got := runExport([]string{"--output", out}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "A=1\n" {
		t.Fatalf("got %q", body)
	}
	info, _ := os.Stat(out)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestRunExport_OutputUnwritable(t *testing.T) {
	fd := startFakeDaemon(t)
	registerListGet(fd, map[string]string{"A": "1"})
	// Write to a path that contains a non-existent directory.
	bad := filepath.Join(t.TempDir(), "missing", "x.env")
	if got := runExport([]string{"--output", bad}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_BadFlag(t *testing.T) {
	if got := runExport([]string{"--zzz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runExport(nil, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_ListErrors(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpList, ipc.CodeLocked, "locked")
	if got := runExport(nil, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunExport_GetErrors(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "A"}}})
	fd.onErr(ipc.OpGet, ipc.CodeLocked, "locked")
	if got := runExport(nil, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

// registerAuthRequiredThenGet sets up the fake daemon so that every get call
// without a password returns auth_required, and every get with a non-empty
// password returns the value. Used to test export --password-stdin.
func registerAuthRequiredThenGet(fd *fakeDaemon, entries map[string]string) {
	metas := make([]ipc.SecretMeta, 0, len(entries))
	for k := range entries {
		metas = append(metas, ipc.SecretMeta{Name: k})
	}
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: metas})
	fd.on(ipc.OpGet, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.GetReq
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, &ipc.ErrMsg{Code: ipc.CodeInternal, Message: err.Error()}
		}
		// Gate: no password → auth_required.
		if len(req.Password) == 0 {
			return nil, &ipc.ErrMsg{
				Code:    ipc.CodeAuthRequired,
				Message: "authorization required",
			}
		}
		v, ok := entries[req.Name]
		if !ok {
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotFound, Message: "no"}
		}
		return ipc.GetResp{Name: req.Name, Value: []byte(v)}, nil
	})
}

// TestRunExport_PasswordStdinAttachedToEveryGet verifies that when
// --password-stdin is set and the daemon returns auth_required,
// export reads the password once from stdin and attaches it to every
// subsequent get call.
func TestRunExport_PasswordStdinAttachedToEveryGet(t *testing.T) {
	fd := startFakeDaemon(t)
	registerAuthRequiredThenGet(fd, map[string]string{"A": "1", "B": "2"})

	// First call per entry will be auth_required; then the password-stdin
	// path reads it and retries every remaining get with it.
	withStdin(t, "mysecretpw\n")
	rc := runExport([]string{"--password-stdin"}, cliScope{})
	if rc != exitOK {
		t.Fatalf("export --password-stdin got rc=%d, want exitOK", rc)
	}

	// Every get call that succeeded must have carried the password.
	getCalls := fd.callsFor(ipc.OpGet)
	if len(getCalls) == 0 {
		t.Fatal("no get calls recorded")
	}
	for _, call := range getCalls {
		var req ipc.GetReq
		requireUnmarshal(t, call.Body, &req)
		if len(req.Password) > 0 && string(req.Password) != "mysecretpw" {
			t.Errorf("get call carried wrong password %q, want mysecretpw", req.Password)
		}
	}
}

// TestRunExport_WithSessionNoPrompt verifies the one-auth contract: when a
// valid session is already loaded by newClient, the daemon returns values
// directly (no CodeAuthRequired), so zero password prompts are needed.
func TestRunExport_WithSessionNoPrompt(t *testing.T) {
	fd := startFakeDaemon(t)
	// registerListGet simulates a daemon that authorizes via session and
	// returns values immediately — no auth_required ever fires.
	registerListGet(fd, map[string]string{"SECRET_A": "alpha", "SECRET_B": "beta"})

	// No --password-stdin and no password in stdin; if any auth prompt
	// fires the test would block or read garbage. The fact that it
	// completes with exitOK proves zero prompts were needed.
	rc := runExport(nil, cliScope{})
	if rc != exitOK {
		t.Fatalf("export with active session got rc=%d, want exitOK (zero auth prompts)", rc)
	}

	// Confirm every get carried no password (session was sufficient).
	getCalls := fd.callsFor(ipc.OpGet)
	if len(getCalls) == 0 {
		t.Fatal("no get calls recorded — daemon was not contacted")
	}
	for _, call := range getCalls {
		var req ipc.GetReq
		requireUnmarshal(t, call.Body, &req)
		if len(req.Password) != 0 {
			t.Errorf("get for %q carried a password %q — expected none (session should be sufficient)",
				req.Name, req.Password)
		}
	}
}

// TestRunExport_AuthRequiredWithoutFlag_HardFails: without --password-stdin, on auth_required
// and non-TTY stdin, auth.Prompt returns ErrNoTerminal immediately without retry.
func TestRunExport_AuthRequiredWithoutFlag_HardFails(t *testing.T) {
	fd := startFakeDaemon(t)
	// Only one entry; get will auth_required on no-password, but no stdin provided
	// and no --password-stdin flag. The non-TTY path should surface the error.
	fd.onOK(ipc.OpList, ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "X"}}})
	fd.onErr(ipc.OpGet, ipc.CodeAuthRequired, "authorization required")
	// Without --password-stdin and with piped stdin (not a TTY), the prompt path
	// will fail with ErrNoTerminal when auth.Prompt detects non-interactive input.
	withStdin(t, "")
	rc := runExport(nil, cliScope{})
	// Should fail because prompting is impossible on non-TTY stdin.
	if rc == exitOK {
		t.Fatalf("export with auth_required and no flag should not succeed, got exitOK")
	}
}
