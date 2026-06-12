// Package fdpass is a leaf package holding the SCM_RIGHTS file-descriptor
// passing primitives (SendFDs / RecvFDs) plus the net.Conn → raw-fd helper
// (ConnFD). It imports nothing from the rest of byn so that BOTH internal/ipc
// (the CLI's CallWithFDs) and internal/privsep (the daemon's spawn transport)
// can use it without creating an import cycle — ipc must not import privsep,
// and this package sits below both.
//
// The exec.spawn transport (NU-5 Task 8) passes the child's three stdio fds
// out-of-band over the same Unix-domain connection that carries the request
// frame: the CLI WriteFrames the request, then SendFDs([]int{0,1,2}); the
// daemon ReadEnvelopes the request, then RecvFDs(3) on the same socket.
package fdpass
