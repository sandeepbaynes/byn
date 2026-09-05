package daemon

// doctor_fda.go adds the macOS Full Disk Access line to `byn doctor`.
//
// It exists because doctor could report a clean bill of health on a machine
// where the daemon was blocked from every project it owns. `byn status` already
// printed an "fda:" line; doctor — the command people actually run when
// something is wrong — did not look at TCC at all, so the one fault that
// silently breaks trust, exec and .byn reads was the one check missing.

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// fdaCheckName is the doctor check id for Full Disk Access.
const fdaCheckName = "daemon.fda"

// fdaChecks returns the Full Disk Access check, or nothing where the question
// is meaningless.
//
// Only macOS has TCC, and only with privsep does it bite: the daemon then runs
// as _byn under launchd, with no relation to the Terminal whose grant the owner
// daemon inherits. Same guard as the "fda:" line in `byn status`, so the two
// commands never disagree about whether FDA applies.
func (d *Daemon) fdaChecks() []ipc.DoctorCheck {
	if runtime.GOOS != "darwin" || !d.cfg.Privsep {
		return nil
	}
	return []ipc.DoctorCheck{fdaCheck(privsep.CheckFDA(), trustedBynPaths(d.cfg.Dir), tccBlocked)}
}

// fdaCheck renders the check from the three facts it needs: whether the daemon
// holds FDA, which .byn files it is expected to read, and whether the OS is in
// fact refusing one. Pure, so a test can describe a machine rather than depend
// on the TCC state of the one running it.
func fdaCheck(granted bool, trusted []string, blocked func(string) bool) ipc.DoctorCheck {
	if granted {
		return ipc.DoctorCheck{
			Name: fdaCheckName, Severity: "ok",
			Detail: "granted — the daemon can read .byn files anywhere",
		}
	}
	// Not granted is not by itself a fault: a project outside the protected
	// folders needs nothing. What makes it a fault is a .byn the owner has
	// already trusted that the daemon cannot open — so measure that, rather
	// than inferring it from where the path happens to live.
	var denied []string
	for _, p := range trusted {
		if blocked(p) {
			denied = append(denied, p)
		}
	}
	if len(denied) == 0 {
		return ipc.DoctorCheck{
			Name: fdaCheckName, Severity: "ok",
			Detail: "not granted — nothing needs it (no trusted .byn is blocked; " +
				"only projects under ~/Documents, ~/Desktop, ~/Downloads or iCloud would be)",
		}
	}
	subject := fmt.Sprintf("%d trusted .byn files", len(denied))
	if len(denied) == 1 {
		subject = "a trusted .byn"
	}
	return ipc.DoctorCheck{
		Name: fdaCheckName, Severity: "fail",
		Detail: fmt.Sprintf("NOT GRANTED — macOS privacy protection (TCC) is blocking the daemon from %s (%s). "+
			"Fix EITHER by moving the project outside ~/Documents, ~/Desktop, ~/Downloads and iCloud "+
			"(e.g. ~/code — no setup needed), OR by granting the byn binary Full Disk Access "+
			"(System Settings > Privacy & Security > Full Disk Access) and restarting the daemon "+
			"(sudo launchctl kickstart -k system/com.sandeepbaynes.byn)",
			subject, denied[0]),
	}
}

// trustedBynPaths lists the .byn files the owner has trusted. A store that will
// not load yields none: doctor reports what it can see, and the trust store's
// own health is not this check's business.
func trustedBynPaths(dir string) []string {
	store, err := trust.Load(dir)
	if err != nil {
		return nil
	}
	paths := make([]string, 0, len(store.Records))
	for _, r := range store.Records {
		paths = append(paths, r.Path)
	}
	return paths
}

// tccBlocked reports whether the OS refuses to open path with EPERM.
//
// EPERM is the signature of a TCC denial and is distinct from the EACCES a
// POSIX permission or ACL failure returns (see annotateReadErr), and from the
// ENOENT of a project that has simply been deleted — neither of which Full Disk
// Access would fix, so neither should be reported as needing it.
func tccBlocked(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- path comes from the owner's trust store
	if err == nil {
		_ = f.Close()
		return false
	}
	return errors.Is(err, syscall.EPERM)
}
