//go:build darwin

package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeatbeltProfileDeniesBynState(t *testing.T) {
	p := seatbeltProfile(SandboxOpts{StateDir: "/var/lib/byn", SocketPath: "/var/lib/byn/daemon.sock"})
	assert.Contains(t, p, "(version 1)")
	assert.Contains(t, p, "(allow default)")
	assert.Contains(t, p, "/var/lib/byn")
	assert.NotContains(t, p, "(deny network*)\n") // network allowed by default
}

func TestSeatbeltProfileNoNetwork(t *testing.T) {
	p := seatbeltProfile(SandboxOpts{StateDir: "/var/lib/byn", NoNetwork: true})
	assert.Contains(t, p, "(deny network*)")
}

func TestSeatbeltProfilePathWithSpaces(t *testing.T) {
	// macOS state dir has spaces — the profile must still be well-formed.
	p := seatbeltProfile(SandboxOpts{StateDir: "/Library/Application Support/byn"})
	assert.Contains(t, p, "Application Support")
}
