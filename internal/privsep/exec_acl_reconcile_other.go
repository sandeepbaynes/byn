//go:build !linux && !darwin

package privsep

// grantFileACLCommand has no meaning where byn has no privsep tier. Returning an
// empty name makes the caller skip rather than spawn something that cannot work.
func grantFileACLCommand(string, string) (string, []string) { return "", nil }
