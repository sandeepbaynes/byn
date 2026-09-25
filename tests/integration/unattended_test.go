//go:build integration

package integration

import (
	"strings"
	"testing"
)

// The import and the doctor check over the real binary and daemon. Producing
// an unattended value needs a trusted .byn and a caller with no session, which
// the daemon suite covers with the origin lookups pinned; this covers the
// wiring and the clean-vault answers every owner will see first.
func TestE2E_ImportUnattendedOnACleanVault(t *testing.T) {
	s := bootstrapUnlocked(t)
	if _, _, code := s.run("v", "put", "API_KEY"); code != 0 {
		t.Fatal("put failed")
	}

	_, errOut := s.mustRun("", "import", "--unattended", "--dry-run")
	if !strings.Contains(errOut, "already protected") {
		t.Fatalf("dry run stderr = %q", errOut)
	}
	_, errOut = s.mustRunPW("", "import", "--unattended", "--all", "--password-stdin")
	if !strings.Contains(errOut, "already protected") {
		t.Fatalf("import stderr = %q", errOut)
	}
	if _, _, code := s.run("", "import", "--unattended", "--replace"); code == 0 {
		t.Fatal("--unattended with a file flag must be refused")
	}

	out, _, _ := s.run("", "doctor", "--json")
	if !strings.Contains(out, `"vault[default].unattended"`) {
		t.Fatalf("doctor --json has no unattended check:\n%s", out)
	}
}
