//go:build linux

package privsep

import "golang.org/x/sys/unix"

// recvFlags requests that the kernel set O_CLOEXEC on all received fds
// atomically inside recvmsg(2) — no race window.
const recvFlags = unix.MSG_CMSG_CLOEXEC

// setCloexec is a no-op on Linux: O_CLOEXEC was already set atomically by
// MSG_CMSG_CLOEXEC in the Recvmsg call above.
func setCloexec(_ []int) {}
