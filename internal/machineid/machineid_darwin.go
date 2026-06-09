//go:build darwin

package machineid

import (
	"os/exec"
	"strings"
)

// platformID returns the macOS IOPlatformUUID — a stable per-machine hardware
// identifier — read from ioreg.
func platformID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output() // #nosec G204 -- fixed args, no user input
	if err != nil {
		return "", err
	}
	if id := parseIOPlatformUUID(string(out)); id != "" {
		return id, nil
	}
	return "", ErrUnavailable
}

// parseIOPlatformUUID extracts the IOPlatformUUID value from ioreg output,
// whose relevant line looks like:  "IOPlatformUUID" = "XXXXXXXX-XXXX-...".
func parseIOPlatformUUID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		v := strings.Trim(strings.TrimSpace(line[eq+1:]), "\"")
		if v != "" {
			return v
		}
	}
	return ""
}
