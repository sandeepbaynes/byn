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
