//go:build linux

package machineid

import (
	"os"
	"strings"
)

// platformID returns the Linux machine-id (systemd / D-Bus), a stable
// per-installation identifier.
func platformID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p) // #nosec G304 -- fixed system paths
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	return "", ErrUnavailable
}
