package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunEnv_NoSubcommand(t *testing.T) {
	if got := runEnv(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnv_Help(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runEnv([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestRunEnv_Unknown(t *testing.T) {
	if got := runEnv([]string{"oops"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvCreate_Positional(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvCreate, ipc.EnvCreateResp{})
	if got := runEnv([]string{"create", "dev"}, cliScope{Project: "p"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	var req ipc.EnvCreateReq
	requireUnmarshal(t, fd.callsFor(ipc.OpEnvCreate)[0].Body, &req)
	if req.Name != "dev" || req.Project != "p" {
		t.Fatalf("req = %+v", req)
	}
}

func TestRunEnvCreate_FromScope(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvCreate, ipc.EnvCreateResp{})
	if got := runEnv([]string{"create"}, cliScope{Env: "staging"}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvCreate_MissingName(t *testing.T) {
	if got := runEnv([]string{"create"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvCreate_TooManyArgs(t *testing.T) {
	if got := runEnv([]string{"create", "a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvCreate_ProjectDefaultedWhenEmpty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvCreate, ipc.EnvCreateResp{})
	_ = runEnv([]string{"create", "dev"}, cliScope{})
	var req ipc.EnvCreateReq
	requireUnmarshal(t, fd.callsFor(ipc.OpEnvCreate)[0].Body, &req)
	if req.Project != "default" {
		t.Fatalf("expected project=default, got %q", req.Project)
	}
}

func TestRunEnvList_Plain(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvList, ipc.EnvListResp{
		Envs: []ipc.EnvInfo{{Name: "default", IsDefault: true}, {Name: "dev"}},
	})
	if got := runEnv([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvList_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvList, ipc.EnvListResp{Envs: []ipc.EnvInfo{{Name: "default", IsDefault: true}}})
	if got := runEnv([]string{"list", "--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvList, ipc.EnvListResp{Envs: nil})
	if got := runEnv([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvDelete_RefusesDefault(t *testing.T) {
	if got := runEnv([]string{"delete", "default"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvDelete_NoName(t *testing.T) {
	if got := runEnv([]string{"delete"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvDelete_TooMany(t *testing.T) {
	if got := runEnv([]string{"delete", "a", "b"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvDelete_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvDelete, ipc.EnvDeleteResp{})
	if got := runEnv([]string{"delete", "dev"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvRename_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpEnvRename, ipc.EnvRenameResp{})
	if got := runEnv([]string{"rename", "a", "b"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvRename_WrongArgs(t *testing.T) {
	if got := runEnv([]string{"rename", "a"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnv_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runEnv([]string{"list"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunEnvCreate_DaemonError(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpEnvCreate, ipc.CodeEnvExists, "dup")
	if got := runEnv([]string{"create", "dev"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}
