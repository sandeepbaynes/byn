package fdpass

import (
	"fmt"
	"net"
)

// ConnFD extracts the raw OS file descriptor from a Unix-domain net.Conn so
// the caller can SendFDs / RecvFDs over it via SCM_RIGHTS. It requires a
// *net.UnixConn (the only conn type byn's IPC uses on the wire).
//
// The fd returned is the LIVE fd the runtime is using for this conn — it is
// NOT a dup. Do not close it; the net.Conn owns it. SendFDs/RecvFDs only read
// from / write to it via sendmsg/recvmsg, they never take ownership.
//
// rc.Control runs the callback with the fd guaranteed valid for the duration of
// the call (the runtime pins it). ConnFD captures the fd inside that window and
// returns it; the immediate SCM op that follows runs against the same live fd.
func ConnFD(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("fdpass: conn %T is not a *net.UnixConn", conn)
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("fdpass: SyscallConn: %w", err)
	}
	var fd int
	cerr := rc.Control(func(raw uintptr) { fd = int(raw) })
	if cerr != nil {
		return 0, fmt.Errorf("fdpass: Control: %w", cerr)
	}
	return fd, nil
}
