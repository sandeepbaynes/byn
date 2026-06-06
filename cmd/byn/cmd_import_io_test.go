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
