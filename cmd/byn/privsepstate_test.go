package main

import "testing"

func stubInstallState(t *testing.T, s privsepInstall) {
	t.Helper()
	orig := privsepInstallStateFn
	t.Cleanup(func() { privsepInstallStateFn = orig })
	privsepInstallStateFn = func() privsepInstall { return s }
}

// A machine with a provisioned data directory and no service is neither
// startable by you nor restartable as a service. Sending anyone to
// `sudo byn restart` there is a dead end: the unit was removed, so the command
// cannot succeed and byn cannot be started at all.
//
// It is the state `byn uninstall` leaves when it keeps the vault, which is the
// documented way to uninstall — so it is reachable by following the docs.
func TestDaemonDownRemedy_NamesWhatWillActuallyWork(t *testing.T) {
	for _, tc := range []struct {
		name        string
		provisioned bool
		state       privsepInstall
		wantCmd     string
	}{
		{"nothing installed", false, privsepNone, "byn start"},
		{"service installed", true, privsepService, sudoByn("restart")},
		{"data but no service", true, privsepDataOnly, sudoByn("setup")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubInstallState(t, tc.state)
			cmd, _ := daemonDownRemedy(tc.provisioned)
			if cmd != tc.wantCmd {
				t.Errorf("remedy = %q, want %q", cmd, tc.wantCmd)
			}
		})
	}
}

// Leftover service accounts are not a service. `byn setup --uninstall` removes
// the unit, the helper and the owner record and deliberately keeps the
// accounts, so judging by the accounts alone declared a bare machine
// "provisioned" and refused to start anything on it.
func TestPrivsepArtifactsPresent_AccountsAloneAreNotAnInstall(t *testing.T) {
	stubInstallState(t, privsepNone)
	if privsepArtifactsPresent() {
		t.Error("no artifacts on disk should not read as provisioned")
	}
	for _, s := range []privsepInstall{privsepService, privsepDataOnly} {
		stubInstallState(t, s)
		if !privsepArtifactsPresent() {
			t.Errorf("state %v should read as provisioned", s)
		}
	}
}
