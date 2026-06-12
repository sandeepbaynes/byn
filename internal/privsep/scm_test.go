//go:build linux || darwin

package privsep

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func socketpair(t *testing.T) (a, b int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	return fds[0], fds[1]
}

func TestSendRecvThreeFDs(t *testing.T) {
	a, b := socketpair(t)
	defer unix.Close(a)
	defer unix.Close(b)

	f, err := os.CreateTemp(t.TempDir(), "scm")
	require.NoError(t, err)
	defer f.Close()
	send := []int{int(f.Fd()), int(f.Fd()), int(f.Fd())}

	require.NoError(t, SendFDs(a, send))

	got, err := RecvFDs(b, 3)
	require.NoError(t, err)
	require.Len(t, got, 3)
	for _, fd := range got {
		assert.Greater(t, fd, 0)
		unix.Close(fd)
	}
}

func TestRecvFDs_WrongCountRejected(t *testing.T) {
	a, b := socketpair(t)
	defer unix.Close(a)
	defer unix.Close(b)
	f, _ := os.CreateTemp(t.TempDir(), "scm")
	defer f.Close()

	require.NoError(t, SendFDs(a, []int{int(f.Fd())}))
	_, err := RecvFDs(b, 3)
	require.Error(t, err)
}

// TestRecvFDs_ClosedSocketErrors exercises the Recvmsg-error path: closing
// one end of the socketpair before calling RecvFDs must return an error.
func TestRecvFDs_ClosedSocketErrors(t *testing.T) {
	a, b := socketpair(t)
	// Close the sending end; RecvFDs on b should immediately return an error.
	unix.Close(a)
	defer unix.Close(b)

	_, err := RecvFDs(b, 1)
	require.Error(t, err)
}
