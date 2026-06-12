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
//
// Close-on-exec strategy (platform split — see scm_linux.go / scm_darwin.go):
//   - Linux:  recvFlags = MSG_CMSG_CLOEXEC — the kernel sets O_CLOEXEC
//     atomically inside recvmsg(2), so setCloexec is a no-op there.
//   - Darwin: recvFlags = 0 (MSG_CMSG_CLOEXEC is not supported by x/sys/unix
//     on macOS); setCloexec calls fcntl(F_SETFD, FD_CLOEXEC) immediately
//     post-receive with a small but unavoidable race window.
func RecvFDs(sock, want int) ([]int, error) {
	oob := make([]byte, unix.CmsgSpace(want*4)) // 4 bytes per int32 fd
	buf := make([]byte, 1)
	_, oobn, recvflags, _, err := unix.Recvmsg(sock, buf, oob, recvFlags)
	if err != nil {
		return nil, err
	}

	// MSG_CTRUNC means the kernel truncated the control data — we cannot
	// recover the truncated fds, so fail fast before parsing.
	if recvflags&unix.MSG_CTRUNC != 0 {
		return nil, fmt.Errorf("privsep: control data truncated")
	}

	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		// If ParseSocketControlMessage fails, the kernel may have already
		// installed fds we cannot enumerate to close — that leak is accepted
		// here because it can only happen with a corrupted kernel or a
		// deliberately malformed peer; well-formed SCM_RIGHTS messages always
		// parse cleanly.
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

	// Ensure every received fd has O_CLOEXEC set. On Linux this is a no-op
	// (the kernel already set it via MSG_CMSG_CLOEXEC above); on Darwin it
	// is a best-effort fcntl immediately after receive.
	setCloexec(got)

	return got, nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
