package main

import (
	"bytes"
	"strings"
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

// doctor --repair elevates itself only when it is not already root and can
// actually ask; with a buffer for stdin there is nobody to prompt, so it
// declines and the caller's message stands.
func TestElevateDoctorRepair_OnlyWhenItCanAndMust(t *testing.T) {
	var out, errBuf bytes.Buffer
	if _, took := elevateDoctorRepair([]string{"--repair"}, 0, strings.NewReader(""), &out, &errBuf); took {
		t.Fatal("root must not re-elevate")
	}
	if _, took := elevateDoctorRepair([]string{"--repair"}, 501, strings.NewReader(""), &out, &errBuf); took {
		t.Fatal("no terminal to prompt on: must decline, not hang on sudo")
	}
	if out.Len() != 0 || errBuf.Len() != 0 {
		t.Fatalf("declining must be silent, got stdout=%q stderr=%q", out.String(), errBuf.String())
	}
}
