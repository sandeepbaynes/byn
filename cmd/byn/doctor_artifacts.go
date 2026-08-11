package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// artifactScanLimit caps how many entries the check walks. Finding one stuck
// file is enough to report the problem, and a project tree can be enormous —
// a health check that takes ten seconds on node_modules is one people stop
// running.
const artifactScanLimit = 20000

// checkStuckArtifacts reports files in the current project that the exec user
// owns and the caller cannot delete.
//
// This is the failure that used to surface as an EACCES from a build tool long
// after byn was involved, with nothing pointing back at byn. Naming it here,
// with the command that fixes it, is the difference between a confusing
// afternoon and a ten-second repair.
func checkStuckArtifacts(cwd string) (healCheck, bool) {
	c := healCheck{Name: "build artifacts writable"}
	if !cliPrivsepProvisioned() {
		return c, false // nothing runs as another user here
	}
	state, err := privsep.LookupState()
	if err != nil || !state.Provisioned {
		return c, false
	}
	execUID := state.ExecUID
	me := os.Getuid()
	if execUID == me {
		return c, false
	}

	var stuck string
	var count, scanned int
	_ = filepath.WalkDir(cwd, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if scanned++; scanned > artifactScanLimit {
			return filepath.SkipAll
		}
		fi, serr := d.Info()
		if serr != nil {
			return nil
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != execUID {
			return nil
		}
		// Owned by the exec user. Only a directory the caller cannot write
		// actually blocks deletion, so report those.
		if d.IsDir() && syscall.Access(path, 2 /* W_OK */) != nil {
			count++
			if stuck == "" {
				if rel, rerr := filepath.Rel(cwd, path); rerr == nil {
					stuck = rel
				} else {
					stuck = path
				}
			}
		}
		return nil
	})

	if count == 0 {
		c.OK = true
		return c, true
	}
	c.Detail = fmt.Sprintf("%d director(ies) here belong to %s and you cannot delete their contents (e.g. %s)",
		count, privsep.ExecUser, stuck)
	c.Fix = "byn repair"
	return c, true
}

// checkHelperFresh reports when the privsep helper on disk is older than the
// byn binary driving it.
//
// The helper that runs lives in libexec with file capabilities and is placed
// there by `byn setup`; installing byn alone leaves it untouched. The two share
// the exec-token protocol, so drift shows up as a helper that does not
// understand something byn has started sending — an error about a flag, from a
// binary nobody remembers installing. Comparing mtimes catches it without
// needing a version handshake.
func checkHelperFresh() (healCheck, bool) {
	c := healCheck{Name: "privsep helper up to date"}
	if !cliPrivsepProvisioned() {
		return c, false
	}
	helper := privsep.HelperDestPath()
	hi, herr := os.Stat(helper)
	if herr != nil {
		return c, false // not installed here; provisioning checks cover that
	}
	self, serr := os.Executable()
	if serr != nil {
		return c, false
	}
	si, serr := os.Stat(self)
	if serr != nil {
		return c, false
	}
	// A day's grace: the two are installed seconds apart normally, and a
	// warning that fires on clock skew is one people learn to ignore.
	if hi.ModTime().Add(24 * time.Hour).After(si.ModTime()) {
		c.OK = true
		return c, true
	}
	c.Detail = fmt.Sprintf("%s is older than byn (%s vs %s) and they share the exec protocol",
		helper, hi.ModTime().Format("2006-01-02"), si.ModTime().Format("2006-01-02"))
	c.Fix = "sudo byn setup"
	return c, true
}
