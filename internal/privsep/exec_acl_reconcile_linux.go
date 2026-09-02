package privsep

// grantFileACLCommand returns the command that gives execUser read+write on one
// existing file.
//
// Split per platform because the two systems do not share an ACL tool: Linux has
// POSIX ACLs and setfacl, macOS has its own ACEs and `chmod +a`. Calling setfacl
// unconditionally, which is what this code did at first, means the whole
// reconcile silently does nothing on macOS — every invocation fails with
// "command not found", the error is dropped because this path is best-effort,
// and the credential lockout it exists to fix stays unfixed.
func grantFileACLCommand(path, execUser string) (string, []string) {
	return "setfacl", []string{"-m", "u:" + execUser + ":rwX", path}
}
