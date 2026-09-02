package privsep

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// aclAccessXattr holds a file's POSIX access ACL. Reading it directly is what
// makes the check affordable: the alternative is spawning getfacl per file, and
// a process spawn per file is the cost this whole pass exists to avoid.
const aclAccessXattr = "system.posix_acl_access"

// POSIX ACL binary layout (linux/posix_acl_xattr.h): a 4-byte version header
// followed by 8-byte entries of {tag uint16, perm uint16, id uint32}. Named-user
// entries carry ACL_USER; every other tag has an undefined id field.
const (
	aclEntrySize = 8
	aclHeaderLen = 4
	aclTagUser   = 0x0002
	aclReadWrite = 0x04 | 0x02
)

// hasExecGrant reports whether path already carries a named-user ACL entry for
// uid with read and write.
//
// This is the idempotency check, and its absence was a bug with no symptom
// beyond slowness: setfacl turns a 0600 file into 0660 by setting the ACL mask,
// which lands in the GROUP bits and leaves other-read clear — so the mode test
// that selects work to do matched a file forever, and every exec re-granted the
// same files. Mode alone cannot answer this, because 0660 from a real group and
// 0660 from an ACL mask are indistinguishable in st_mode. The ACL itself can.
//
// False on any error: an unreadable or ACL-less file is one we have not granted,
// so the caller tries, and setfacl reports the real problem.
func hasExecGrant(path string, uid int) bool {
	if uid < 0 {
		return false
	}
	buf := make([]byte, 1024)
	n, err := unix.Getxattr(path, aclAccessXattr, buf)
	if err != nil || n < aclHeaderLen {
		return false
	}
	for off := aclHeaderLen; off+aclEntrySize <= n; off += aclEntrySize {
		tag := binary.LittleEndian.Uint16(buf[off:])
		perm := binary.LittleEndian.Uint16(buf[off+2:])
		id := binary.LittleEndian.Uint32(buf[off+4:])
		if tag == aclTagUser && int(id) == uid && perm&aclReadWrite == aclReadWrite {
			return true
		}
	}
	return false
}
