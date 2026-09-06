package privsep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceExecPathFromPlist_FirstProgramArgument(t *testing.T) {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.sandeepbaynes.byn</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/byn</string>
    <string>daemon</string>
    <string>start</string>
  </array>
</dict>
</plist>`
	got, err := ServiceExecPathFromPlist([]byte(plist))
	require.NoError(t, err)
	assert.Equal(t, "/usr/local/bin/byn", got)
}

func TestServiceExecPathFromPlist_NoProgram(t *testing.T) {
	_, err := ServiceExecPathFromPlist([]byte("<plist><dict><key>Label</key><string>x</string></dict></plist>"))
	assert.ErrorIs(t, err, ErrNoServiceExecPath)
	_, err = ServiceExecPathFromPlist(nil)
	assert.ErrorIs(t, err, ErrNoServiceExecPath)
}
