package main

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestDoctorExitCode_AllOK(t *testing.T) {
	r := ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "a", Severity: "ok"},
		{Name: "b", Severity: "ok"},
		{Name: "c", Severity: "warn"},
	}}
	if got := doctorExitCode(r); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
}

func TestDoctorExitCode_AnyFailFails(t *testing.T) {
	r := ipc.DoctorResp{Checks: []ipc.DoctorCheck{
		{Name: "a", Severity: "ok"},
		{Name: "b", Severity: "fail"},
	}}
	if got := doctorExitCode(r); got != exitErr {
		t.Fatalf("got %d, want exitErr", got)
	}
}

func TestDoctorExitCode_EmptyChecks(t *testing.T) {
	r := ipc.DoctorResp{}
	if got := doctorExitCode(r); got != exitOK {
		t.Fatalf("got %d, want exitOK", got)
	}
}
