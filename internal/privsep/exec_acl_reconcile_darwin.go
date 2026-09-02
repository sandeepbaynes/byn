package privsep

// grantFileACLCommand returns the command that gives execUser read+write on one
// existing file.
//
// `chmod +a` rather than setfacl, which does not exist on macOS. No inheritance
// flags: this grants access to a file that already exists and was locked down
// after the fact, which is the opposite case from the trust-time grant that sets
// inheritance on a directory.
//
// Adding an ACE that is already present is refused by chmod rather than
// duplicated, so re-running is safe. It is not free, though — unlike the Linux
// path this cannot cheaply tell "already granted" from "needs granting" before
// spawning, because reading a macOS ACL means parsing `ls -le` per file. The
// pass is bounded to the paths a .byn explicitly declares, which keeps that to a
// handful of files, and the alternative — spawning nothing and leaving the
// lockout unfixed — is worse.
func grantFileACLCommand(path, execUser string) (string, []string) {
	return "chmod", []string{"+a", aceArg(execUser, "read,write"), path}
}
