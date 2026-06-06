package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunDoctor_OK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "vault.open", Severity: "ok"},
		{Name: "vault.unlock", Severity: "warn", Detail: "locked"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_FailExitsNonZero(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "audit.chain", Severity: "fail", Detail: "broken at 3"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "a", Severity: "ok"},
	}})
	if got := runDoctor([]string{"--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_UnknownSeverity(t *testing.T) {
	// Ensure the "?" branch is exercised.
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpDoctor, ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "weird", Severity: "mystery", Detail: "?"},
	}})
	if got := runDoctor(nil, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_BadFlag(t *testing.T) {
	if got := runDoctor([]string{"--nope"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunDoctor_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runDoctor(nil, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}
