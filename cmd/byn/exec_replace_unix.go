//go:build unix

package main

import "golang.org/x/sys/unix"

// syscallExec replaces this process with argv[0].
//
// A real execve, not a subprocess: the editor owns the terminal for its whole
// life, so a parent left in the middle would have to forward signals, window
// resizes and the exit status correctly in order to contribute nothing.
func syscallExec(path string, argv, env []string) error {
	return unix.Exec(path, argv, env)
}
