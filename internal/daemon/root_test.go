package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// refuseRoot is a pure predicate driving the daemon's start-time root refusal.
// The table covers the three operationally meaningful states: root without the
// override (refuse), root WITH the override (allow), and a normal owner-UID dev
// run (always allowed — the common case must be unaffected).
func TestRefuseRoot(t *testing.T) {
	cases := []struct {
		name      string
		euid      int
		allowRoot bool
		wantErr   bool
	}{
		{name: "root_without_override_refused", euid: 0, allowRoot: false, wantErr: true},
		{name: "root_with_override_allowed", euid: 0, allowRoot: true, wantErr: false},
		{name: "owner_uid_unaffected", euid: 501, allowRoot: false, wantErr: false},
		{name: "owner_uid_with_override_still_fine", euid: 501, allowRoot: true, wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseRoot(tc.euid, tc.allowRoot)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("refuseRoot(%d, %v) = nil, want error", tc.euid, tc.allowRoot)
				}
				if !errors.Is(err, errRefuseRoot) {
					t.Fatalf("refuseRoot(%d, %v) = %v, want errRefuseRoot", tc.euid, tc.allowRoot, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("refuseRoot(%d, %v) = %v, want nil", tc.euid, tc.allowRoot, err)
			}
		})
	}
}

// The refusal message must be actionable (project rule): it has to name the
// root cause, the safe path forward, and the explicit override — without
// over-claiming a defense it cannot make against an existing root attacker.
func TestRefuseRootMessageActionable(t *testing.T) {
	msg := errRefuseRoot.Error()
	for _, want := range []string{
		"root",          // names the condition
		"_byn",          // names WHY: defeats the privsep service user
		"privilege sep", // explains the consequence
		"--allow-root",  // names HOW to override
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message missing %q; got:\n%s", want, msg)
		}
	}
	// Honest scope: the message must NOT promise protection against an already-
	// root attacker.
	if !strings.Contains(msg, "not a defense") && !strings.Contains(msg, "posture hygiene") {
		t.Errorf("refusal message should disclaim being a root defense; got:\n%s", msg)
	}
}

// The daemon start path is wired to refuseRoot: when started as uid 0 without
// --allow-root it returns the refusal before binding anything. This exercises
// the real Start path; it only runs when actually root (CI privsep job), and
// skips cleanly otherwise so no test requires being root. The pure predicate
// table above covers the logic deterministically without root.
func TestStart_RefusesRootWhenNotAllowed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root — refuseRoot logic is covered by TestRefuseRoot without root")
	}
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test", OwnerUID: 12345, AllowRoot: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.Start(context.Background()); !errors.Is(err, errRefuseRoot) {
		t.Fatalf("Start as root = %v, want errRefuseRoot", err)
	}
	// No pidfile/socket should have been created — refusal happens first.
	if _, statErr := os.Stat(d.pidPath); statErr == nil {
		t.Error("pidfile created despite root refusal — refusal must precede side effects")
	}
}
