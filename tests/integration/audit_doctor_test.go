//go:build integration

// Tests for Slice 4 audit + Slice 5 doctor.
package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestE2E_Audit_TailShowsRecentEvents(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("hello", "put", "GREETING"); code != 0 {
		t.Fatalf("put failed")
	}
	stdout, _, code := s.run("", "audit", "tail", "--lines", "5")
	if code != 0 {
		t.Fatalf("audit tail exited %d", code)
	}
	// Should reference the put we just did.
	if !strings.Contains(stdout, "put") {
		t.Fatalf("audit tail did not surface our put:\n%s", stdout)
	}
}

func TestE2E_Audit_TailJSON(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v", "put", "K"); code != 0 {
		t.Fatalf("put failed")
	}
	stdout, _ := s.mustRun("", "audit", "tail", "--json")
	var got []map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("audit tail --json: not valid JSON:\n%s\nerr=%v", stdout, err)
	}
	if len(got) == 0 {
		t.Fatalf("audit tail --json returned no events")
	}
	// First event we expect: vault.unlock at bootstrap.
	hasUnlock := false
	for _, e := range got {
		if op, _ := e["op"].(string); op == "vault.unlock" {
			hasUnlock = true
		}
	}
	if !hasUnlock {
		t.Fatalf("audit log missing vault.unlock event:\n%s", stdout)
	}
}

func TestE2E_Audit_VerifyOnCleanLog(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v", "put", "K"); code != 0 {
		t.Fatalf("put failed")
	}
	stdout, _, code := s.run("", "audit", "verify")
	if code != 0 {
		t.Fatalf("audit verify on clean log exited %d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "intact") {
		t.Fatalf("audit verify clean log message missing:\n%s", stdout)
	}
}

func TestE2E_Doctor_AllOK(t *testing.T) {
	s := bootstrapUnlocked(t)
	stdout, _, code := s.run("", "doctor")
	if code != 0 {
		t.Fatalf("doctor exited %d:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "daemon") || !strings.Contains(stdout, "vault[default]") {
		t.Fatalf("doctor output missing expected checks:\n%s", stdout)
	}
	// No FAIL line.
	if strings.Contains(stdout, "FAIL") {
		t.Fatalf("doctor showed FAIL on a healthy install:\n%s", stdout)
	}
}

func TestE2E_Doctor_JSON(t *testing.T) {
	s := bootstrapUnlocked(t)
	stdout, _ := s.mustRun("", "doctor", "--json")
	var got struct {
		Checks []struct {
			Name, Severity, Detail string
		}
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("doctor --json not valid JSON: %v\n%s", err, stdout)
	}
	if len(got.Checks) < 2 {
		t.Fatalf("doctor --json: too few checks: %+v", got)
	}
	hasDaemon := false
	for _, c := range got.Checks {
		if c.Name == "daemon" {
			hasDaemon = true
			if c.Severity != "ok" {
				t.Fatalf("daemon check not ok: %+v", c)
			}
		}
	}
	if !hasDaemon {
		t.Fatalf("doctor --json: no daemon check: %+v", got)
	}
}
