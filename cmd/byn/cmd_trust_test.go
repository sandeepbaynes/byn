package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// withCWD changes directory for the duration of a test, restoring it after.
func withCWD(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func writeDotByn(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".byn")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestDefaultBynPath_PositionalArg(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse([]string{"/explicit/path"})
	if got := defaultBynPath(fs); got != "/explicit/path" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultBynPath_FallbackToCWD(t *testing.T) {
	dir := t.TempDir()
	withCWD(t, dir)
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse(nil)
	if filepath.Base(defaultBynPath(fs)) != ".byn" {
		t.Fatalf("want a path ending in .byn")
	}
}

func TestRunTrust_DispatchHelp(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runTrust([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestBynTargetVault_Helper(t *testing.T) {
	if v := bynTargetVault([]byte("[scope]\nvault = \"acme\"\n")); v != "acme" {
		t.Fatalf("got %q", v)
	}
}

// ---- grant -------------------------------------------------------------

// The headline CLI guarantee: `byn trust` sends the target vault + the
// master password to the daemon (granting is never a local write).
func TestRunTrustAdd_GrantsViaDaemonWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustGrantBulk, ipc.TrustGrantBulkResp{
		Results: []ipc.TrustGrantResult{{Path: "/canon/.byn", SHA256: strings.Repeat("a", 64)}},
	})
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "s3cret\n")

	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	calls := fd.callsFor(ipc.OpTrustGrantBulk)
	if len(calls) != 1 {
		t.Fatalf("expected 1 bulk grant call, got %d", len(calls))
	}
	var req ipc.TrustGrantBulkReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Vault != "a" {
		t.Errorf("vault = %q, want a (from .byn [scope])", req.Vault)
	}
	if string(req.Password) != "s3cret" {
		t.Errorf("password not forwarded to the daemon: %q", req.Password)
	}
	if len(req.Paths) != 1 || req.Paths[0] != tpath {
		t.Errorf("paths = %v, want [%q]", req.Paths, tpath)
	}
}

func TestRunTrustAdd_DaemonRejectsWrongPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpTrustGrantBulk, ipc.CodeWrongPassword, "could not authorize: wrong password")
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "wrong\n")
	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitDaemonErr {
		t.Fatalf("got %d, want exitDaemonErr", got)
	}
}

func TestRunTrustAdd_MissingFile(t *testing.T) {
	t.Setenv("BYN_DIR", t.TempDir())
	if got := runTrustAdd([]string{filepath.Join(t.TempDir(), "nope")}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_BadFlag(t *testing.T) {
	if got := runTrustAdd([]string{"--bogus"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_DaemonDown(t *testing.T) {
	noDaemon(t)
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "pw\n")
	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitDaemonDown {
		t.Fatalf("got %d, want exitDaemonDown", got)
	}
}

// ---- untrust -----------------------------------------------------------

func TestRunUntrust_ViaDaemon(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustRemove, ipc.TrustRemoveResp{Removed: true})
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	if n := len(fd.callsFor(ipc.OpTrustRemove)); n != 1 {
		t.Fatalf("expected 1 remove call, got %d", n)
	}
}

func TestRunUntrust_NotTrusted_StillOK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustRemove, ipc.TrustRemoveResp{Removed: false})
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_BadFlag(t *testing.T) {
	if got := runUntrust([]string{"--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_DaemonDown(t *testing.T) {
	noDaemon(t)
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

// ---- list --------------------------------------------------------------

func TestRunTrustList_ViaDaemon(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{Entries: []ipc.TrustEntry{
		{Path: "/a/.byn", SHA256: strings.Repeat("b", 64)},
	}})
	if got := runTrustList(nil); got != exitOK {
		t.Fatalf("plain got %d", got)
	}
	if got := runTrustList([]string{"--json"}); got != exitOK {
		t.Fatalf("json got %d", got)
	}
}

func TestRunTrustList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{})
	if got := runTrustList(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_BadFlag(t *testing.T) {
	if got := runTrustList([]string{"--zz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runTrustList(nil); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrust_ListBranch(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{})
	if got := runTrust([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("list got %d", got)
	}
	if got := runTrust([]string{"ls"}, cliScope{}); got != exitOK {
		t.Fatalf("ls got %d", got)
	}
}
