//go:build darwin

package fdpass

import "golang.org/x/sys/unix"

// recvFlags is 0 on Darwin: x/sys/unix does not expose MSG_CMSG_CLOEXEC for
// macOS, so we cannot ask the kernel to set O_CLOEXEC atomically. Instead,
// setCloexec calls fcntl(F_SETFD, FD_CLOEXEC) immediately after receive; see
// that function for the race-window note.
const recvFlags = 0

// setCloexec sets FD_CLOEXEC on each fd via fcntl. This is best-effort:
// there is a tiny race window between Recvmsg returning and this call where
// another goroutine could fork+exec and inherit the fd. macOS does not support
// MSG_CMSG_CLOEXEC in x/sys/unix, so this post-receive approach is the
// closest available equivalent. In practice the window is sub-microsecond and
// goroutine scheduling makes it extremely unlikely; the real daemon should
// avoid forking concurrently with fd receipt.
func setCloexec(fds []int) {
	for _, fd := range fds {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC)
	}
}
