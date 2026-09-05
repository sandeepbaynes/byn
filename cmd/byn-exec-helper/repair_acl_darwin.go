//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
)

// macOS has no setfacl. ACLs are set with `chmod +a "<principal> allow <perms>"`,
// and the permission vocabulary is per-file-type: the directory rights
// (list/search/add_file/add_subdirectory) are meaningless on a regular file.
//
// Neither entry carries file_inherit/directory_inherit. Repair exists to reach
// files that ALREADY exist; the inheriting entry that covers future ones is put
// back separately, on the project root, by the owner CLI.
const (
	repairFileACEPerms = "read,write,delete"
	repairDirACEPerms  = "list,search,add_file,add_subdirectory,delete,read,write"
)

// aclPrincipal renders uid the way this platform's ACL tool accepts it.
//
// macOS chmod cannot translate a numeric id — `chmod +a "501 allow read"` fails
// with "Unable to translate '501' to a UUID" — so the uid has to become a name.
// It is still read from the kernel (the caller's real uid) and never taken from
// argv, which is the property that matters: the helper is setuid, so a username
// on the command line would let anyone who can run it grant access to a user of
// their choosing.
func aclPrincipal(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("no account for uid %d: %w", uid, err)
	}
	if u.Username == "" {
		return "", fmt.Errorf("uid %d has an empty username", uid)
	}
	return u.Username, nil
}

// aclToolAvailable reports whether the platform ACL tool is present, so a
// machine missing it fails once with a clear message instead of once per file.
func aclToolAvailable() error {
	if _, err := exec.LookPath("chmod"); err != nil {
		return fmt.Errorf("chmod not found in PATH: %w", err)
	}
	return nil
}

// aclOwnerCmd builds the command granting owner read/write access to path.
// `chmod +a` is idempotent: re-adding an identical entry is a no-op that exits
// 0, so repeated repairs do not accumulate duplicate ACEs.
func aclOwnerCmd(path, owner string, isDir bool) *exec.Cmd {
	perms := repairFileACEPerms
	if isDir {
		perms = repairDirACEPerms
	}
	// #nosec G204 -- fixed binary; owner is a username resolved from the
	// caller's kernel uid and path came from walking a directory we just read.
	return exec.Command("chmod", "+a", owner+" allow "+perms, path)
}
