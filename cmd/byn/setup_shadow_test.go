package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestSetupWarn_SaysWhenVersionsDisagree.
//
// sudo resolves against secure_path, never the user's PATH. So after
// `GOBIN=~/.local/bin go install …`, a plain `sudo byn setup` does not run the
// byn just installed — it runs whatever older copy sits in /usr/local/bin, which
// provisions happily and reports success. The person is told it worked while the
// binary they upgraded to was never involved.
func TestSetupWarn_SaysWhenVersionsDisagree(t *testing.T) {
	var buf bytes.Buffer
	warnIfProvisioningAnOlderByn(&buf, []bynInstall{
		{Path: "/usr/local/bin/byn", Version: "0.5.2", OnPath: true},
		{Path: "/home/x/.local/bin/byn", Version: "0.6.4"},
	})
	out := buf.String()
	if out == "" {
		t.Fatal("two byns at different versions must produce a warning")
	}
	for _, want := range []string{"0.5.2", "0.6.4", "/usr/local/bin/byn", "secure_path"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning must name the versions, the paths and why; missing %q in:\n%s", want, out)
		}
	}
	// The remedy has to be present, or the warning is only alarming.
	if !strings.Contains(out, "command -v byn") {
		t.Errorf("the warning must give the command that picks a specific byn:\n%s", out)
	}
}

// Several copies of the SAME build is the ordinary state of a machine that has
// been installed more than one way. Warning there would train people to ignore
// the warning that matters.
func TestSetupWarn_QuietWhenTheyAgree(t *testing.T) {
	var buf bytes.Buffer
	warnIfProvisioningAnOlderByn(&buf, []bynInstall{
		{Path: "/usr/local/bin/byn", Version: "0.6.4"},
		{Path: "/home/x/go/bin/byn", Version: "0.6.4"},
	})
	if buf.Len() != 0 {
		t.Fatalf("identical versions are not a disagreement:\n%s", buf.String())
	}
}

// One byn is the common case and must be silent.
func TestSetupWarn_QuietWithASingleInstall(t *testing.T) {
	var buf bytes.Buffer
	warnIfProvisioningAnOlderByn(&buf, []bynInstall{{Path: "/usr/local/bin/byn", Version: "0.6.4"}})
	if buf.Len() != 0 {
		t.Fatalf("a single install must produce no warning:\n%s", buf.String())
	}
}
