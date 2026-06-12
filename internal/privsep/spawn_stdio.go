//go:build linux || darwin

package privsep

import (
	"fmt"
	"os"
	"syscall"
)

// dupStdio dups the three stdio fds from req into private file descriptors and
// returns them as *os.File wrappers. The caller must close the returned files
// when they are no longer needed (e.g. after cmd.Run returns).
//
// We dup the caller's stdio fds so cmd owns separate fds; the daemon's
// req.Stdin/out/err are never closed by the Spawner.
//
// If any dup fails the already-created dups are closed and an error is returned.
func dupStdio(req SpawnReq) (stdin, stdout, stderr *os.File, err error) {
	inFd, e := syscall.Dup(req.Stdin)
	if e != nil {
		return nil, nil, nil, fmt.Errorf("privsep: dupStdio: dup stdin: %w", e)
	}

	outFd, e := syscall.Dup(req.Stdout)
	if e != nil {
		_ = syscall.Close(inFd)
		return nil, nil, nil, fmt.Errorf("privsep: dupStdio: dup stdout: %w", e)
	}

	errFd, e := syscall.Dup(req.Stderr)
	if e != nil {
		_ = syscall.Close(inFd)
		_ = syscall.Close(outFd)
		return nil, nil, nil, fmt.Errorf("privsep: dupStdio: dup stderr: %w", e)
	}

	return os.NewFile(uintptr(inFd), "stdin"),
		os.NewFile(uintptr(outFd), "stdout"),
		os.NewFile(uintptr(errFd), "stderr"),
		nil
}
