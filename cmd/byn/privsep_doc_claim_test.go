package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocs_DoNotCallPrivsepVestigial guards a security claim that was false and
// came back.
//
// The docs said `[security] privsep` was vestigial — that it gated only a
// server-side path the CLI no longer used, and setting it changed nothing. It is
// in fact the switch: `byn exec` asks the daemon whether privsep is on
// (cmd_exec.go, privsepOn = st.Privsep) and the daemon answers from that config
// key. A machine can be fully provisioned — service users, spawn helper, ACLs —
// and still run every exec child at the owner's UID because the flag is unset.
//
// The claim was identified as wrong and reverted once already, and survived in
// four files. Telling somebody a security switch does nothing is an invitation
// to turn it off, so it gets a test rather than another careful reading.
func TestDocs_DoNotCallPrivsepVestigial(t *testing.T) {
	roots := []string{"../../README.md", "../../docs"}
	var offenders []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // an unreadable tree is not this test's business
			}
			// Generated HTML mirrors the markdown; checking the source is enough.
			if !strings.HasSuffix(path, ".md") {
				return nil
			}
			// The changelog and the release notes RECORD the wrong claim in the
			// course of correcting it, and must go on being able to. What this
			// guards is documentation that describes the product as it is now.
			base := filepath.Base(path)
			if base == "CHANGELOG.md" || base == "releases.md" {
				return nil
			}
			body, rerr := os.ReadFile(path) // #nosec G304 -- repo-relative doc paths
			if rerr != nil {
				return nil
			}
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, "privsep") && strings.Contains(strings.ToLower(line), "vestigial") {
					offenders = append(offenders, path+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("the docs call [security] privsep vestigial again. It is the switch: "+
			"byn exec reads it via st.Privsep, so a provisioned machine with the flag "+
			"unset runs exec children at the owner's UID.\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// TestDocs_DoNotTeachManualKillOfExecChildren guards against byn printing
// advice that both fails and causes the failure it appears to solve.
//
// `byn ps` help used to end with:
//
//	$ kill 33887
//	$ kill $(pgrep -P 33887)
//	$ pkill -f "byn exec"
//
// Under privilege separation none of that works as written. The children run as
// _byn-exec, so a signal from the owner's shell is refused with EPERM — and
// kill(1) prints nothing when it cannot signal, so it looks like it worked. The
// one command that DOES succeed, killing the wrapper, is worse than the ones
// that fail: it leaves the children running with no parent. That is exactly how
// a machine ends up with dev servers holding ports and no process group left to
// signal them by, which is the state `byn kill` exists to prevent and which
// cost a real debugging session.
//
// Held by a test because it is documentation teaching a habit, and a habit
// outlives the paragraph that taught it.
func TestDocs_DoNotTeachManualKillOfExecChildren(t *testing.T) {
	help, ok := commandHelp["ps"]
	if !ok {
		t.Fatal("no help registered for `byn ps`")
	}
	// The advice must not be RECOMMENDED. It may still be named, because the
	// text explains why not to use it — so this looks for the recipes, not the
	// bare command names.
	for _, recipe := range []string{
		`pkill -f "byn exec"`,
		"kill $(pgrep -P",
	} {
		if strings.Contains(help, recipe) {
			t.Errorf("`byn ps` help recommends %q; under privsep it fails with EPERM "+
				"or orphans the children — point at `byn kill` instead", recipe)
		}
	}
	if !strings.Contains(help, "byn kill") {
		t.Error("`byn ps` help must point at `byn kill` — it is the only thing that " +
			"can signal a _byn-exec child, and the whole reason the command exists")
	}
}
