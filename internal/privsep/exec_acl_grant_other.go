//go:build !linux

package privsep

// hasExecGrant is Linux-only. POSIX access ACLs are read through a Linux xattr
// name, and the macOS tier does its ownership work a different way entirely, so
// elsewhere this reports nothing known and the caller simply re-grants.
func hasExecGrant(string, int) bool { return false }
