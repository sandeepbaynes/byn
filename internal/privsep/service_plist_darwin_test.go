//go:build darwin

package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reader must agree with the writer: whatever path launchDaemonPlist is
// given is what ServiceExecPathFromPlist hands back.
func TestServiceExecPathFromPlist_RoundTrip(t *testing.T) {
	for _, p := range []string{"/usr/local/bin/byn", "/opt/homebrew/bin/byn", "/Users/x/go/bin/byn"} {
		got, err := ServiceExecPathFromPlist([]byte(launchDaemonPlist(p)))
		require.NoError(t, err)
		assert.Equal(t, p, got)
	}
}
