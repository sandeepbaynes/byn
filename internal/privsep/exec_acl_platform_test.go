package privsep

import (
	"runtime"
	"strings"
	"testing"
)

// TestGrantFileACLCommand_UsesThePlatformsOwnTool guards a defect that only
// exists on the machine you are not sitting at.
//
// The reconcile shelled out to setfacl unconditionally. macOS has no setfacl —
// it has `chmod +a` — so on a Mac every invocation failed with "command not
// found", the error was dropped because the pass is deliberately best-effort,
// and the credential lockout the whole thing exists to fix stayed unfixed. It
// built, it vetted, it passed every test, and it did nothing.
//
// A cross-compile catches a platform stub that does not compile. Nothing catches
// one that compiles and is wrong, except asserting what it produces.
func TestGrantFileACLCommand_UsesThePlatformsOwnTool(t *testing.T) {
	name, args := grantFileACLCommand("/tmp/creds.json", "_byn-exec")
	joined := name + " " + strings.Join(args, " ")

	switch runtime.GOOS {
	case "linux":
		if name != "setfacl" {
			t.Fatalf("linux must use setfacl, got %q", joined)
		}
		if !strings.Contains(joined, "u:_byn-exec:rwX") {
			t.Fatalf("the ACE must name the exec user with rwX: %q", joined)
		}
	case "darwin":
		if name != "chmod" {
			t.Fatalf("macOS has no setfacl; it must use chmod +a, got %q", joined)
		}
		if !strings.Contains(joined, "+a") || !strings.Contains(joined, "_byn-exec allow") {
			t.Fatalf("the ACE must be a chmod +a allow rule for the exec user: %q", joined)
		}
		// Inheritance belongs on the trust-time directory grant, not here: this
		// repairs a file that already exists and was locked down afterwards.
		if strings.Contains(joined, "file_inherit") || strings.Contains(joined, "directory_inherit") {
			t.Fatalf("a per-file repair must not set inheritance flags: %q", joined)
		}
	default:
		if name != "" {
			t.Fatalf("a platform with no privsep tier must produce no command, got %q", joined)
		}
	}
	// Whatever the platform, the file being repaired has to be in the command.
	if name != "" && !strings.Contains(joined, "/tmp/creds.json") {
		t.Fatalf("the path is missing from the command: %q", joined)
	}
}
