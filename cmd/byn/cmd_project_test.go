package main

import (
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunProject_NoSubcommand(t *testing.T) {
	if got := runProject(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestRunProject_HelpAliases(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runProject([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q: got %d", h, got)
		}
	}
}

func TestRunProject_UnknownSubcommand(t *testing.T) {
	if got := runProject([]string{"oops"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectCreate_PositionalArg(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectCreate, ipc.ProjectCreateResp{})
	if got := runProject([]string{"create", "billing"}, cliScope{Vault: "v"}); got != exitOK {
		t.Fatalf("exit = %d", got)
	}
	calls := fd.callsFor(ipc.OpProjectCreate)
	if len(calls) != 1 {
		t.Fatalf("calls = %d", len(calls))
	}
	var req ipc.ProjectCreateReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Name != "billing" || req.Vault != "v" {
		t.Fatalf("req = %+v", req)
	}
}

func TestRunProjectCreate_FromScopeFlag(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectCreate, ipc.ProjectCreateResp{})
	if got := runProject([]string{"create"}, cliScope{Project: "fromflag"}); got != exitOK {
		t.Fatalf("exit=%d", got)
	}
	var req ipc.ProjectCreateReq
	requireUnmarshal(t, fd.callsFor(ipc.OpProjectCreate)[0].Body, &req)
	if req.Name != "fromflag" {
		t.Fatalf("Name = %q", req.Name)
	}
}

func TestRunProjectCreate_NoNameErr(t *testing.T) {
	if got := runProject([]string{"create"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectCreate_TooManyArgs(t *testing.T) {
	if got := runProject([]string{"create", "a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectCreate_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runProject([]string{"create", "x"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectCreate_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpProjectCreate, ipc.CodeProjectExists, "dup")
	if got := runProject([]string{"create", "x"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectList_Plain(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectList, ipc.ProjectListResp{
		Projects: []ipc.ProjectInfo{{Name: "default", CreatedAt: time.Now()}},
	})
	if got := runProject([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectList_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectList, ipc.ProjectListResp{Projects: []ipc.ProjectInfo{{Name: "x"}}})
	if got := runProject([]string{"list", "--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectList, ipc.ProjectListResp{Projects: nil})
	if got := runProject([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectList_BadFlag(t *testing.T) {
	if got := runProject([]string{"list", "--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectDelete_RefusesDefault(t *testing.T) {
	if got := runProject([]string{"delete", "default"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectDelete_NoName(t *testing.T) {
	if got := runProject([]string{"delete"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectDelete_TooManyArgs(t *testing.T) {
	if got := runProject([]string{"delete", "a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectDelete_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectDelete, ipc.ProjectDeleteResp{})
	if got := runProject([]string{"delete", "demo"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunProjectRename_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpProjectRename, ipc.ProjectRenameResp{})
	if got := runProject([]string{"rename", "old", "new"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	var req ipc.ProjectRenameReq
	requireUnmarshal(t, fd.callsFor(ipc.OpProjectRename)[0].Body, &req)
	if req.OldName != "old" || req.NewName != "new" {
		t.Fatalf("req = %+v", req)
	}
}

func TestRunProjectRename_WrongArgCount(t *testing.T) {
	if got := runProject([]string{"rename"}, cliScope{}); got != exitErr {
		t.Fatalf("zero args got %d", got)
	}
	if got := runProject([]string{"rename", "only"}, cliScope{}); got != exitErr {
		t.Fatalf("one arg got %d", got)
	}
	if got := runProject([]string{"rename", "a", "b", "c"}, cliScope{}); got != exitErr {
		t.Fatalf("three args got %d", got)
	}
}

func TestRunProjectRename_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpProjectRename, ipc.CodeProjectNotFound, "nope")
	if got := runProject([]string{"rename", "a", "b"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestProjectOrDefault_AndVaultOrDefault(t *testing.T) {
	if projectOrDefault("") != "default" {
		t.Fatal("empty should default")
	}
	if projectOrDefault("x") != "x" {
		t.Fatal("explicit should pass through")
	}
	if vaultOrDefault("") != "default" {
		t.Fatal("empty should default")
	}
	if vaultOrDefault("x") != "x" {
		t.Fatal("explicit should pass through")
	}
}
