package main

import (
	"strings"
	"testing"
)

func TestCmdRootClass(t *testing.T) {
	cases := map[string]rootClass{
		"status": classOwner, "get": classOwner, "exec": classOwner,
		"unlock": classOwner, "config-auth": classOwner, "web": classOwner,
		"restart": classRootWhenProvisioned, "reload": classRootWhenProvisioned,
		"stop":  classRootWhenProvisioned,
		"start": classStart,
		// setup/migrate/daemon/doctor self-manage their own root logic.
		"setup": classSelfChecks, "migrate": classSelfChecks,
		"daemon": classSelfChecks, "doctor": classSelfChecks,
		"version": classNeutral, "help": classNeutral, "bogus": classNeutral,
	}
	for cmd, want := range cases {
		if got := cmdRootClass(cmd); got != want {
			t.Errorf("cmdRootClass(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestEnforceRootPolicy(t *testing.T) {
	const root, owner = 0, 501
	prov := func(b bool) func() bool { return func() bool { return b } }

	cases := []struct {
		name        string
		cmd         string
		euid        int
		provisioned bool
		wantRefuse  bool
		wantSubstr  string
	}{
		{"owner cmd as root refused", "status", root, true, true, "runs as you, not root"},
		{"owner cmd as you runs", "get", owner, true, false, ""},
		{"config-auth as root refused", "config-auth", root, true, true, "runs as you, not root"},
		{"start as root refused", "start", root, true, true, "don't start byn as root"},
		{"start as you not refused by guard", "start", owner, true, false, ""},
		{"restart as you+provisioned needs root", "restart", owner, true, true, "needs root"},
		{"restart as you not-provisioned runs", "restart", owner, false, false, ""},
		{"restart as root runs", "restart", root, true, false, ""},
		{"stop as you+provisioned needs root", "stop", owner, true, true, "needs root"},
		{"setup as root ignored by guard", "setup", root, true, false, ""},
		{"doctor as root ignored by guard", "doctor", root, true, false, ""},
		{"version neutral as root runs", "version", root, true, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			got := enforceRootPolicy(tc.cmd, tc.euid, prov(tc.provisioned), &b)
			if got != tc.wantRefuse {
				t.Fatalf("refuse = %v, want %v (out=%q)", got, tc.wantRefuse, b.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(b.String(), tc.wantSubstr) {
				t.Errorf("message %q missing %q", b.String(), tc.wantSubstr)
			}
			if !tc.wantRefuse && b.Len() != 0 {
				t.Errorf("expected no output when not refusing, got %q", b.String())
			}
		})
	}
}

// TestEnforceRootPolicy_LazyProvision proves the provisioned probe is only
// consulted for service-management commands (not on the owner-command path).
func TestEnforceRootPolicy_LazyProvision(t *testing.T) {
	called := false
	fn := func() bool { called = true; return false }
	var b strings.Builder
	// An owner command run as you must NOT consult the provisioned probe.
	enforceRootPolicy("get", 501, fn, &b)
	if called {
		t.Error("provisioned probe was called for an owner command — should be lazy")
	}
	// A service-management command DOES consult it.
	enforceRootPolicy("restart", 501, fn, &b)
	if !called {
		t.Error("provisioned probe was NOT called for restart")
	}
}
