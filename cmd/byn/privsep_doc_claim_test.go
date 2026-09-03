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
