//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

// aclPrincipal renders uid the way this platform's ACL tool accepts it. setfacl
// takes a numeric uid directly, which is the safest form available: no name
// lookup, and nothing from argv reaches the command line.
func aclPrincipal(uid int) (string, error) {
	return strconv.Itoa(uid), nil
}

// aclToolAvailable reports whether the platform ACL tool is present, so a
// machine missing it fails once with a clear message instead of once per file.
func aclToolAvailable() error {
	if _, err := exec.LookPath("setfacl"); err != nil {
		return fmt.Errorf("setfacl not found in PATH (install acl): %w", err)
	}
	return nil
}

// aclOwnerCmd builds the command granting owner read/write access to path.
// rwX gives execute only where it already applies (directories, already-x
// files), so a repaired data file does not come back executable. isDir is
// unused here because rwX already encodes that distinction.
func aclOwnerCmd(path, owner string, _ bool) *exec.Cmd {
	// #nosec G204 -- fixed binary; owner is a numeric uid from the kernel and
	// path came from walking a directory we just read.
	return exec.Command("setfacl", "-m", "u:"+owner+":rwX", path)
}
