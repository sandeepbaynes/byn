//go:build darwin

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const helperConfigPath = "/Library/Application Support/byn/exec-helper.conf"

// dropTo drops privileges to the given uid/gid on Darwin (macOS).
// Drop order: setgroups([gid]) → setregid(g,g) → setreuid(u,u) → verify via readback.
// macOS does not have POSIX capabilities, so there is no cap-clearing step.
// Never returns nil unless all steps succeed; on any error the caller must abort.
func dropTo(uid, gid int) error {
	// 1. Restrict supplementary groups to only [gid].
	if err := unix.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}

	// 2. Drop GID first (must precede UID drop; a non-root process cannot
	//    change its GID).
	if err := unix.Setregid(gid, gid); err != nil {
		return fmt.Errorf("setregid(%d): %w", gid, err)
	}

	// 3. Drop UID.
	if err := unix.Setreuid(uid, uid); err != nil {
		return fmt.Errorf("setreuid(%d): %w", uid, err)
	}

	// 4. Verify via kernel readback — the only reliable check on macOS where
	//    /proc does not exist.
	if gotUID := unix.Getuid(); gotUID != uid {
		return fmt.Errorf("uid readback: got %d, want %d", gotUID, uid)
	}
	if gotEUID := unix.Geteuid(); gotEUID != uid {
		return fmt.Errorf("euid readback: got %d, want %d", gotEUID, uid)
	}
	if gotGID := unix.Getgid(); gotGID != gid {
		return fmt.Errorf("gid readback: got %d, want %d", gotGID, gid)
	}
	if gotEGID := unix.Getegid(); gotEGID != gid {
		return fmt.Errorf("egid readback: got %d, want %d", gotEGID, gid)
	}

	// Mark the child undumpable before execve (no-op on macOS — PR_SET_DUMPABLE
	// is a Linux prctl; macOS gates cross-UID args/env reads in the kernel and
	// the daemon is shipped with the hardened runtime). Kept in the drop
	// sequence so the Linux/macOS helpers share one shape.
	if err := setUndumpable(); err != nil {
		return fmt.Errorf("setting undumpable: %w", err)
	}

	return nil
}

// setUndumpable is a no-op on macOS: there is no PR_SET_DUMPABLE, and the
// cross-UID env-read protection comes from the kernel's sysctl_procargsx UID
// check plus the daemon's hardened runtime (see .goreleaser.yaml). Present so
// dropTo has the same shape as the Linux helper.
func setUndumpable() error { return nil }

// readEnvFD reads NUL-delimited KEY=VALUE pairs from the given file descriptor.
// fd 3 is used by convention so env vars are never visible on argv.
func readEnvFD(fd uintptr) ([]string, error) {
	f := os.NewFile(fd, "env-pipe")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not valid", fd)
	}
	defer f.Close() //nolint:errcheck // pipe; close error does not lose data we already read

	sc := bufio.NewScanner(f)
	sc.Split(splitNUL)
	var pairs []string
	for sc.Scan() {
		tok := sc.Text()
		if tok == "" {
			continue
		}
		pairs = append(pairs, tok)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading env fd: %w", err)
	}
	return pairs, nil
}

// splitNUL is a bufio.SplitFunc that splits on NUL bytes (\x00).
func splitNUL(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// execTarget replaces the current process via execve. It requires an ABSOLUTE
// target path and does NO PATH resolution — the daemon resolves PATH itself,
// unprivileged, removing the PATH-poisoning vector from the privileged helper.
func execTarget(argv []string, env []string) error {
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("target %q is not an absolute path", argv[0])
	}
	return unix.Exec(argv[0], argv, env)
}
