package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// runRepairArtifacts gives the owner back access to files a privsep exec child
// created in this project.
//
// Trust now sets a default ACL so new artifacts stay writable, but a default
// entry only reaches files created after it — a project already built under byn
// keeps a .next and a node_modules/.vite owned by the service user that the
// owner cannot delete, because removing a file needs write on its directory.
// Only the file's owner or root can change that, so the work happens in the
// helper, as the service user.
func runRepairArtifacts(args []string, _ cliScope) int {
	target := "."
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target = args[0]
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	if !cliPrivsepProvisioned() {
		fmt.Fprintf(os.Stderr, "%s\n", dim("privsep is not provisioned here, so nothing runs as another user — nothing to repair."))
		return exitOK
	}
	// Put the inherited entry back FIRST. Repairing only the files that exist
	// treats the symptom: without a default ACL on the directory, the very next
	// build creates a fresh set of artifacts nobody can delete, and the repair
	// has to be run again forever. A project trusted before this existed — or
	// one whose ACL was cleared — needs the cause fixed too.
	if u, uerr := user.Current(); uerr == nil {
		home, _ := os.UserHomeDir()
		// Forced: repair is called when a tree is known to be wrong, so the
		// inheritable entry on the root proves nothing about what is beneath it.
		if gerr := privsep.GrantProjectACLForce(ownerACLRun, abs, home, u.Username); gerr != nil {
			fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Note:"),
				dim(fmt.Sprintf("could not refresh the inherited ACL on %s: %v", abs, gerr)))
		}
	}

	// The helper reads the caller's uid itself rather than taking a username
	// from us, so there is no name to pass and nothing to spoof.
	helper := privsep.HelperDestPath()
	out, rerr := exec.Command(helper, "--repair-owner", abs).CombinedOutput() //nolint:gosec // operator-installed helper at a fixed path
	text := strings.TrimSpace(string(out))
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "%s repairing %s: %v\n", boldRed("Error:"), abs, rerr)
		if text != "" {
			fmt.Fprintln(os.Stderr, dim(text))
		}
		return exitErr
	}
	// The helper prints the count on its last line.
	count := text
	if i := strings.LastIndex(text, "\n"); i >= 0 {
		count = strings.TrimSpace(text[i+1:])
	}
	if count == "0" {
		fmt.Fprintf(os.Stderr, "%s\n", dim("nothing to repair — no files here belong to the exec user."))
		return exitOK
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", cyan("Repaired"),
		dim(fmt.Sprintf("%s file(s) under %s — you can delete them now.", count, abs)))
	return exitOK
}
