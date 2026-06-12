//go:build linux || darwin

package privsep

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SendFDs sends the given fds over a connected Unix-domain socket via
// SCM_RIGHTS. The receiver gets duplicated fds in its own table.
func SendFDs(sock int, fds []int) error {
	rights := unix.UnixRights(fds...)
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

// RecvFDs receives EXACTLY want fds over the socket. Any other count is an
// error and every fd actually received is closed (no leak). The control buffer
// is capped to want fds so a malicious sender cannot flood us.
func RecvFDs(sock, want int) ([]int, error) {
	oob := make([]byte, unix.CmsgSpace(want*4)) // 4 bytes per int32 fd
	buf := make([]byte, 1)
	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return nil, err
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	var got []int
	for _, scm := range scms {
		fds, perr := unix.ParseUnixRights(&scm)
		if perr != nil {
			closeAll(got)
			return nil, perr
		}
		got = append(got, fds...)
	}
	if len(got) != want {
		closeAll(got)
		return nil, fmt.Errorf("privsep: expected %d fds, got %d", want, len(got))
	}
	return got, nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
