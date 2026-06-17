package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocketMode(t *testing.T) {
	// Unprovisioned: daemon runs as the owner, 0600 is private + sufficient.
	assert.Equal(t, "-rw-------", socketMode(false).String())
	// Provisioned: daemon is _byn, the owner is a different UID and must be able
	// to connect(); the socket is peercred-gated, so 0666 only reaches the gate.
	assert.Equal(t, "-rw-rw-rw-", socketMode(true).String())
}
