//go:build linux || darwin

package privsep

import "github.com/sandeepbaynes/byn/internal/fdpass"

// SendFDs / RecvFDs are thin re-exports of the leaf fdpass package. The SCM
// primitives live in internal/fdpass so that BOTH internal/ipc (the CLI's
// CallWithFDs) and this package can use them without an import cycle (ipc must
// not import privsep). privsep keeps these aliases so its existing callers and
// tests keep working unchanged.

// SendFDs sends the given fds over a connected Unix-domain socket via
// SCM_RIGHTS. See fdpass.SendFDs.
func SendFDs(sock int, fds []int) error { return fdpass.SendFDs(sock, fds) }

// RecvFDs receives EXACTLY want fds over the socket. See fdpass.RecvFDs.
func RecvFDs(sock, want int) ([]int, error) { return fdpass.RecvFDs(sock, want) }
