//go:build !darwin && !linux

package machineid

// platformID has no stable source on unsupported platforms. byn only ships
// darwin + linux; this keeps the package buildable elsewhere (dev tooling).
func platformID() (string, error) { return "", ErrUnavailable }
