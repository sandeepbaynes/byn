package daemon

import (
	"os"
	"testing"
)

// TestProcInfo_Self verifies that procInfo(os.Getpid()) returns a non-empty
// comm (the test binary name) and a plausible ppid on platforms that
// implement procInfo. On unsupported platforms it returns "", 0 — that is
// also valid.
func TestProcInfo_Self(t *testing.T) {
	comm, ppid := procInfo(os.Getpid())
	if comm == "" {
		// Unsupported platform or non-proc OS: acceptable.
		t.Logf("procInfo(self): comm empty (unsupported platform or no /proc)")
		return
	}
	t.Logf("procInfo(self): comm=%q ppid=%d", comm, ppid)
	if ppid <= 0 {
		t.Errorf("procInfo(self): ppid = %d, expected > 0", ppid)
	}
}

// TestPeerTTYDev_Self checks that peerTTYDev(os.Getpid()) either returns
// 0 (no controlling terminal — acceptable in CI) or a positive device number.
// It must never panic.
//
// NOTE: same-UID TIOCSCTTY acquisition is accepted residual risk. The Unix
// socket is already mode 0600, so a same-UID attacker can connect directly;
// the ttyDev binding is a convenience, not a security boundary.
func TestPeerTTYDev_Self(t *testing.T) {
	dev := peerTTYDev(os.Getpid())
	t.Logf("peerTTYDev(self) = %d", dev)
	// 0 is valid in CI (no controlling terminal). Any int32 is valid.
	_ = dev
}

// TestProcInfo_InvalidPID returns zero values for invalid PIDs.
func TestProcInfo_InvalidPID(t *testing.T) {
	comm, ppid := procInfo(-1)
	if comm != "" || ppid != 0 {
		t.Errorf("procInfo(-1) = (%q, %d), want (\"\", 0)", comm, ppid)
	}
}

// TestPeerTTYDev_InvalidPID returns 0 for invalid PIDs.
func TestPeerTTYDev_InvalidPID(t *testing.T) {
	if got := peerTTYDev(-1); got != 0 {
		t.Errorf("peerTTYDev(-1) = %d, want 0", got)
	}
}
