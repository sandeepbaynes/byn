//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// verifyOwnedBy checks that the file described by fi is owned by the given
// uid:gid. It is the ownership half of the post-setup verify: the system data
// dir must be owned by the _byn service account so the privsep daemon can read
// its state. A negative uid/gid disables that side of the check (a relocate may
// have skipped the chown in a test). On unix it reads the underlying stat; the
// non-unix stub (which `byn setup` never reaches — provisioning is unsupported
// there) is a no-op.
func verifyOwnedBy(fi os.FileInfo, uid, gid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not read file ownership (unexpected stat type)")
	}
	if uid >= 0 && int(st.Uid) != uid {
		return fmt.Errorf("owned by UID %d, expected %d (run `byn setup` as root)", st.Uid, uid)
	}
	if gid >= 0 && int(st.Gid) != gid {
		return fmt.Errorf("owned by GID %d, expected %d (run `byn setup` as root)", st.Gid, gid)
	}
	return nil
}
