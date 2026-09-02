package main

import "testing"

// TestDoctor_NoticesADaemonThatIsNotTheInstalledByn is named after the machine
// that produced it: byn was installed, `sudo byn restart` reported success, the
// service never restarted, and doctor printed a clean bill of health with the
// old daemon's version sitting in the OK line. `byn status` caught it; doctor,
// the command you run to find out whether an upgrade landed, did not.
func TestDoctor_NoticesADaemonThatIsNotTheInstalledByn(t *testing.T) {
	checks := daemonIsInstalledBynCheck(true, func() string { return "0.5.5-5-g48a20f5" }, "0.5.5-7-gd58d4e7")
	if len(checks) != 1 || checks[0].OK {
		t.Fatalf("a daemon two commits behind the CLI must fail the check, got %+v", checks)
	}
	if got := checks[0].Detail; got == "" {
		t.Fatal("the check must name both versions — the whole point is telling them apart")
	}
}

func TestDoctor_MatchingVersionsPass(t *testing.T) {
	checks := daemonIsInstalledBynCheck(true, func() string { return "0.5.6" }, "0.5.6")
	if len(checks) != 1 || !checks[0].OK {
		t.Fatalf("matching versions must pass, got %+v", checks)
	}
}

// A down daemon already failed "daemon running"; a second line about its
// version is noise stacked on the real finding.
func TestDoctor_SaysNothingWhenTheDaemonIsDown(t *testing.T) {
	if got := daemonIsInstalledBynCheck(false, func() string { return "x" }, "y"); got != nil {
		t.Fatalf("want no check when the daemon is down, got %+v", got)
	}
}

// An unknown version is not a mismatch. Reporting one would turn "byn could not
// ask" into "your install is broken", which is worse than staying quiet.
func TestDoctor_SaysNothingWhenAVersionIsUnknown(t *testing.T) {
	if got := daemonIsInstalledBynCheck(true, func() string { return "" }, "0.5.6"); got != nil {
		t.Fatalf("want no check when the daemon version is unknown, got %+v", got)
	}
}
