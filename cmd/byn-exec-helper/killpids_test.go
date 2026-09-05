package main

import (
	"syscall"
	"testing"
)

func TestKillPidsRequested_ParsesListAndSignal(t *testing.T) {
	pids, sig, ok := killPidsRequested([]string{"byn-exec-helper", "--kill-pids", "10,20,30"})
	if !ok {
		t.Fatal("expected a parse")
	}
	if len(pids) != 3 || pids[0] != 10 || pids[2] != 30 {
		t.Fatalf("pids = %v", pids)
	}
	if sig != syscall.SIGTERM {
		t.Errorf("default signal = %v, want SIGTERM", sig)
	}
	_, sig, ok = killPidsRequested([]string{"x", "--kill-pids", "10", "--signal", "KILL"})
	if !ok || sig != syscall.SIGKILL {
		t.Fatalf("KILL: ok=%v sig=%v", ok, sig)
	}
}

// The parse is a security boundary, not input tidying: kill(2) reads 0 as the
// caller's whole process group and -1 as every process it may signal, so a pid
// below 2 reaching syscall.Kill would turn a targeted cleanup into a
// machine-wide one — as the exec service user, which is the account every byn
// child runs under.
func TestKillPidsRequested_RefusesWholesaleTargets(t *testing.T) {
	for _, arg := range []string{"0", "-1", "1", "10,0", "10,-1", "-1,10", "10,1"} {
		if pids, _, ok := killPidsRequested([]string{"x", "--kill-pids", arg}); ok {
			t.Errorf("%q was accepted as %v; it must be refused", arg, pids)
		}
	}
}

func TestKillPidsRequested_RefusesJunk(t *testing.T) {
	cases := [][]string{
		{"x"},                                       // no flag
		{"x", "--kill-pids"},                        // flag with no value
		{"x", "--kill-pids", ""},                    // empty list
		{"x", "--kill-pids", "abc"},                 // not a number
		{"x", "--kill-pids", "10", "--signal"},      // signal with no value
		{"x", "--kill-pids", "10", "--signal", "9"}, // numeric signal not allowed
		{"x", "--kill-pids", "10", "--signal", "HUP"},
	}
	for _, args := range cases {
		if _, _, ok := killPidsRequested(args); ok {
			t.Errorf("%v was accepted", args)
		}
	}
}

func TestKillPidsRequested_CapsTheList(t *testing.T) {
	csv := ""
	for i := 0; i <= maxKillPids; i++ {
		if i > 0 {
			csv += ","
		}
		csv += "1000"
	}
	if _, _, ok := killPidsRequested([]string{"x", "--kill-pids", csv}); ok {
		t.Fatal("a list over the cap must be refused")
	}
}

func TestKillPgrpRequested_StillRejectsSmallPgids(t *testing.T) {
	for _, arg := range []string{"0", "1", "-5", "junk"} {
		if _, ok := killPgrpRequested([]string{"x", "--kill-pgrp", arg}); ok {
			t.Errorf("%q accepted", arg)
		}
	}
	if pgid, ok := killPgrpRequested([]string{"x", "--kill-pgrp", "4242"}); !ok || pgid != 4242 {
		t.Fatalf("pgid=%d ok=%v", pgid, ok)
	}
}
