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
