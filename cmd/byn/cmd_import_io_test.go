package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// registerPutCounter installs a put handler that tallies create-only
// rejections vs writes. If failOn is non-empty, a put with that name
// returns the given errMsg instead.
func registerPutCounter(fd *fakeDaemon, failOn string, failErr *ipc.ErrMsg) *sync.Map {
	seen := &sync.Map{}
	fd.on(ipc.OpPut, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.PutReq
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, &ipc.ErrMsg{Code: ipc.CodeInternal, Message: err.Error()}
		}
		if failOn != "" && req.Name == failOn {
			return nil, failErr
		}
		seen.Store(req.Name, string(req.Value))
		return ipc.PutResp{}, nil
	})
	return seen
}

func TestRunImport_DotenvViaFile(t *testing.T) {
	fd := startFakeDaemon(t)
	seen := registerPutCounter(fd, "", nil)
	path := filepath.Join(t.TempDir(), "input.env")
	if err := os.WriteFile(path, []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := runImport([]string{path}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	count := 0
	seen.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("got %d puts, want 2", count)
	}
}

func TestRunImport_DotenvViaStdin(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	withStdin(t, "A=1\n")
	if got := runImport([]string{"--format=env"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_DryRun(t *testing.T) {
	fd := startFakeDaemon(t)
	// No put registered; if dry-run actually called daemon, the call
	// would 404. (Make sure not to register OpPut at all.)
	_ = fd
	withStdin(t, "A=1\n")
	if got := runImport([]string{"--dry-run", "--format=env"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_BadFormat(t *testing.T) {
	withStdin(t, "no = at all = mess")
	if got := runImport([]string{"--format=banana"}, cliScope{}); got != exitErr {
		// Unknown format is treated as the parser dispatching to fmtUnknown.
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_TooManyPathArgs(t *testing.T) {
	if got := runImport([]string{"a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_MissingFile(t *testing.T) {
	if got := runImport([]string{"/no/such/file"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_UnknownFormatStdin(t *testing.T) {
	withStdin(t, "AB CD no format hint")
	if got := runImport(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_EmptyBody(t *testing.T) {
	withStdin(t, "")
	// fmt sniff returns fmtUnknown for empty body → exitErr.
	if got := runImport([]string{"--format=env"}, cliScope{}); got != exitOK {
		t.Fatalf("empty dotenv got %d", got)
	}
}

func TestRunImport_ParseError(t *testing.T) {
	withStdin(t, "no_equals_here\n")
	if got := runImport([]string{"--format=env"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_DaemonDown(t *testing.T) {
	// runImport's per-entry put error path returns exitErr (not the
	// usual exitDaemonDown from handleCallError) because the loop
	// formats the error inline. This codifies that behavior.
	noDaemon(t)
	withStdin(t, "A=1\n")
	if got := runImport([]string{"--format=env"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_SkipExisting(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "A", &ipc.ErrMsg{Code: ipc.CodeAlreadyExists, Message: "exists"})
	withStdin(t, "A=1\nB=2\n")
	if got := runImport([]string{"--skip-existing", "--format=env"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_PutErrorAbortsRun(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "A", &ipc.ErrMsg{Code: ipc.CodeBadName, Message: "bad"})
	withStdin(t, "A=1\n")
	if got := runImport([]string{"--format=env"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_DashIsStdin(t *testing.T) {
	fd := startFakeDaemon(t)
	registerPutCounter(fd, "", nil)
	withStdin(t, "A=1\n")
	if got := runImport([]string{"--format=env", "-"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunImport_BadFlag(t *testing.T) {
	if got := runImport([]string{"--zz"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

// registerAuthRequiredThenPut sets up the fake daemon so that every put
// call without a password returns CodeAuthRequired, and every put with a
// non-empty password succeeds. Used to test import --password-stdin.
func registerAuthRequiredThenPut(fd *fakeDaemon) *sync.Map {
	seen := &sync.Map{}
	fd.on(ipc.OpPut, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.PutReq
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
		seen.Store(req.Name, string(req.Value))
		return ipc.PutResp{}, nil
	})
	return seen
}

// TestRunImport_WithSessionNoPrompt verifies the one-auth contract: when a
// valid session is already loaded by newClient, the daemon accepts puts
// directly (no CodeAuthRequired), so zero password prompts are needed.
func TestRunImport_WithSessionNoPrompt(t *testing.T) {
	fd := startFakeDaemon(t)
	seen := registerPutCounter(fd, "", nil)

	withStdin(t, "A=1\nB=2\n")
	// No --password-stdin, no password in stdin. If any auth prompt fired,
	// the test would block or produce exitErr. exitOK proves zero prompts.
	rc := runImport([]string{"--format=env"}, cliScope{})
	if rc != exitOK {
		t.Fatalf("import with active session got rc=%d, want exitOK (zero auth prompts)", rc)
	}

	// Confirm both entries were written and neither carried a password.
	count := 0
	seen.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("got %d puts, want 2", count)
	}
	putCalls := fd.callsFor(ipc.OpPut)
	for _, call := range putCalls {
		var req ipc.PutReq
		requireUnmarshal(t, call.Body, &req)
		if len(req.Password) != 0 {
			t.Errorf("put for %q carried a password — expected none (session should be sufficient)",
				req.Name)
		}
	}
}

// TestRunImport_PasswordStdinAttachedToEveryPut verifies that when
// --password-stdin is set and the daemon returns auth_required,
// import reads the password once from stdin and attaches it to every
// subsequent put call (including the retry for the first entry).
func TestRunImport_PasswordStdinAttachedToEveryPut(t *testing.T) {
	fd := startFakeDaemon(t)
	seen := registerAuthRequiredThenPut(fd)

	// Password is first in stdin; the entries follow via a file to avoid
	// stdin contention (withStdin replaces os.Stdin with a pipe, but the
	// import file path is read before stdin, so we use a real temp file).
	path := writeTempEnv(t, "A=1\nB=2\n")
	withStdin(t, "mysecretpw\n")
	rc := runImport([]string{"--password-stdin", path}, cliScope{})
	if rc != exitOK {
		t.Fatalf("import --password-stdin got rc=%d, want exitOK", rc)
	}

	// Both entries must have been stored.
	count := 0
	seen.Range(func(_, _ any) bool { count++; return true })
	if count != 2 {
		t.Fatalf("got %d successful puts, want 2", count)
	}

	// Every put that succeeded must have carried the password.
	putCalls := fd.callsFor(ipc.OpPut)
	// There will be one failed attempt (no password) + one retry + all
	// remaining (with password). Verify the ones with a password used the
	// right value.
	for _, call := range putCalls {
		var req ipc.PutReq
		requireUnmarshal(t, call.Body, &req)
		if len(req.Password) > 0 && string(req.Password) != "mysecretpw" {
			t.Errorf("put for %q carried wrong password %q, want mysecretpw",
				req.Name, req.Password)
		}
	}
}

// writeTempEnv is a test helper that writes an .env file in a temp dir
// and returns its path.
func writeTempEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeTempEnv: %v", err)
	}
	return path
}

// TestRunImport_AuthRequiredWithoutFlag_HardFails verifies that when the
// daemon fires CodeAuthRequired and no --password-stdin flag is given and
// stdin is not a TTY (pipe), import fails immediately without hanging.
func TestRunImport_AuthRequiredWithoutFlag_HardFails(t *testing.T) {
	fd := startFakeDaemon(t)
	registerAuthRequiredThenPut(fd)

	// Non-TTY stdin with no --password-stdin: prompting would fail with
	// ErrNoTerminal; import must surface that as a hard failure.
	withStdin(t, "")
	path := writeTempEnv(t, "A=1\n")
	rc := runImport([]string{path}, cliScope{})
	if rc == exitOK {
		t.Fatalf("import with auth_required and no flag should not succeed, got exitOK")
	}
}
