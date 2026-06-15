// Package privsep implements privilege separation for the byn daemon.
// When provisioned, the exec child runs as the service user _byn-exec,
// which is a distinct UID from the daemon owner. Provisioning is performed
// by `byn setup` which creates the service users. If the users are absent
// the daemon falls back to running exec children as the calling user
// (no privilege separation). The package is opt-in: callers check
// LookupState before deciding whether to engage privsep.
package privsep

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Service user names created by `byn setup`.
const (
	DaemonUser = "_byn"
	ExecUser   = "_byn-exec"
)

// Sentinel errors returned by LookupState / lookupState.
var (
	// ErrNotProvisioned is returned when the service users have not been created.
	ErrNotProvisioned = errors.New("privsep: not provisioned (run `byn setup`)")

	// ErrInvalidProvisioning is returned when the exec service UID collides with
	// the current process owner — privilege separation would be ineffective.
	ErrInvalidProvisioning = errors.New("privsep: invalid provisioning (service UID collides with owner)")

	// ErrUnsupported is returned on platforms where privsep is not implemented.
	ErrUnsupported = errors.New("privsep: unsupported platform")

	// errUserNotFound is an internal sentinel used by osLookup and tests.
	errUserNotFound = errors.New("user not found")
)

// State holds the resolved UIDs for the service users.
type State struct {
	Provisioned bool
	ExecUID     int
	ExecGID     int
}

// currentUID returns the effective UID of the calling process.
func currentUID() int {
	return os.Getuid()
}

// traverseAncestors returns startDir followed by each of its ancestor
// directories up to and INCLUDING home (or the filesystem root if home is not
// an ancestor). A service user must have execute/search ("traverse") permission
// on EVERY one of these to open a file beneath startDir — a single restrictive
// intermediate (e.g. a 0700 ~/Documents) otherwise blocks access even when the
// leaf file itself is readable. The result is granted idempotently, so passing
// already-world-traversable dirs (e.g. /Users) is harmless.
func traverseAncestors(startDir, home string) []string {
	home = filepath.Clean(home)
	var dirs []string
	d := startDir
	for {
		dirs = append(dirs, d)
		parent := filepath.Dir(d)
		if d == home || d == parent { // reached home (inclusive) or the root
			break
		}
		d = parent
	}
	return dirs
}

// uidLookup is a function that resolves a username to its UID and GID.
// It returns errUserNotFound when the user does not exist.
type uidLookup func(name string) (uid, gid int, err error)

// osLookup is the production uidLookup backed by os/user.
func osLookup(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, errUserNotFound
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// LookupState resolves the provisioning state using the real OS user database.
func LookupState() (State, error) {
	return lookupState(osLookup)
}

// LookupDaemonUser resolves the uid/gid of the _byn service account that owns
// the daemon's system data tree. `byn migrate` chowns the adopted tree to this
// uid/gid so the provisioned daemon (which runs as _byn) can read its state. It
// returns [ErrNotProvisioned] when the account is absent — migrate adopts with
// the correct ownership, it does NOT create the service user (that is `byn
// setup`'s job), so a missing _byn must tell the user to run setup first.
func LookupDaemonUser() (uid, gid int, err error) {
	return lookupDaemonUser(osLookup)
}

// lookupDaemonUser is the testable core of LookupDaemonUser.
func lookupDaemonUser(lookup uidLookup) (uid, gid int, err error) {
	duid, dgid, lerr := lookup(DaemonUser)
	if lerr != nil {
		return 0, 0, ErrNotProvisioned
	}
	return duid, dgid, nil
}

// lookupState resolves the provisioning state using the provided uidLookup.
// It is the testable core of LookupState.
func lookupState(lookup uidLookup) (State, error) {
	euid, egid, err := lookup(ExecUser)
	if err != nil {
		// Exec user absent → not provisioned; not an error.
		return State{Provisioned: false}, nil
	}
	if euid == currentUID() {
		return State{}, ErrInvalidProvisioning
	}
	return State{
		Provisioned: true,
		ExecUID:     euid,
		ExecGID:     egid,
	}, nil
}
