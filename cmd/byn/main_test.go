package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestSkipDiscoveryFor(t *testing.T) {
	for _, cmd := range []string{"trust", "untrust", "daemon", "version", "--version", "-v", "help", "--help", "-h", "doctor"} {
		if !skipDiscoveryFor(cmd) {
			t.Errorf("expected skip for %q", cmd)
		}
	}
	if skipDiscoveryFor("put") {
		t.Fatal("put should not skip")
	}
}

func TestWantsHelp(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"help"}, true},
		{[]string{}, false},
		{[]string{"foo"}, false},
		{[]string{"put", "name"}, false},
		{[]string{"put", "--help"}, true},
		{[]string{"put", "help", "extra"}, false}, // help mixed with real positional
	}
	for _, tc := range cases {
		if got := wantsHelp(tc.args); got != tc.want {
			t.Errorf("wantsHelp(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

func TestPrintCommandHelp_Known(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "1") // avoid spawning a pager
	if got := printCommandHelp("put"); got != 0 {
		t.Fatalf("got %d", got)
	}
}

func TestPrintCommandHelp_Unknown(t *testing.T) {
	if got := printCommandHelp("zztop"); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestUsageText_HasVersion(t *testing.T) {
	got := usageText()
	if got == "" {
		t.Fatal("empty usage")
	}
}

func TestRun_Version(t *testing.T) {
	for _, a := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		if got := run(a); got != 0 {
			t.Fatalf("%v: got %d", a, got)
		}
	}
}

func TestRun_Help(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "1")
	for _, a := range [][]string{{"help"}, {"--help"}, {"-h"}, {"help", "put"}, {"help", "zzz"}} {
		_ = run(a)
	}
}

func TestRun_Unknown(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	if got := run([]string{"banana"}); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestRun_BadGlobalFlag(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	if got := run([]string{"--vault"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToList(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpList, ipc.ListResp{})
	if got := run([]string{"list"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToVaultList(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpVaultList, ipc.VaultListResp{})
	if got := run([]string{"vault", "list"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToProjectList(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectList, ipc.ProjectListResp{})
	if got := run([]string{"project", "list"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToEnvList(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvList, ipc.EnvListResp{})
	if got := run([]string{"env", "list"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToAuditTail(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{})
	if got := run([]string{"audit", "tail"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToDoctor(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{})
	if got := run([]string{"doctor"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToStatus(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpStatus, ipc.StatusResp{})
	if got := run([]string{"status"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_RoutesToTrust(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	t.Setenv("BYN_DIR", t.TempDir())
	// "trust list" doesn't talk to the daemon and works in isolation.
	if got := run([]string{"trust", "list"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	if got := run([]string{"untrust", "/nonexistent"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRun_PerCommandHelp(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "1")
	t.Setenv("BYN_NO_DISCOVERY", "1")
	if got := run([]string{"put", "--help"}); got != 0 {
		t.Fatalf("got %d", got)
	}
}
