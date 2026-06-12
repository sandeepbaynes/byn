//go:build linux

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const helperConfigPath = "/var/lib/byn/exec-helper.conf"

// dropTo drops privileges to the given uid/gid on Linux.
// Drop order: setgroups([gid]) → setresgid(g,g,g) → setresuid(u,u,u) → verify → clearAllCaps.
// Never returns nil unless all steps succeed; on any error the caller must abort.
func dropTo(uid, gid int) error {
	// 1. Restrict supplementary groups to only [gid].
	if err := unix.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}

	// 2. Drop GID first (must be before UID; once UID is dropped we lose
	//    the ability to call setresgid on some kernels if saved-set-uid is gone).
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid(%d): %w", gid, err)
	}

	// 3. Drop UID.
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid(%d): %w", uid, err)
	}

	// 4. Verify the drop succeeded by reading /proc/self/status.
	if err := verifyDropped(uid, gid); err != nil {
		return fmt.Errorf("post-drop verification failed: %w", err)
	}

	// 5. Clear all capabilities so this process cannot regain privilege.
	if err := clearAllCaps(); err != nil {
		return fmt.Errorf("clearing capabilities: %w", err)
	}

	return nil
}

// verifyDropped reads /proc/self/status and confirms all four UID and GID
// fields (real, effective, saved, filesystem) equal the expected values.
// This is the authoritative check on Linux — the kernel writes these fields
// directly from the credential struct.
func verifyDropped(uid, gid int) error {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return fmt.Errorf("open /proc/self/status: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only fd; close error is inconsequential

	want := fmt.Sprintf("%d\t%d\t%d\t%d", uid, uid, uid, uid)
	wantG := fmt.Sprintf("%d\t%d\t%d\t%d", gid, gid, gid, gid)
	uidOK, gidOK := false, false

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			got := strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
			if got != want {
				return fmt.Errorf("uid mismatch: got %q, want %q", got, want)
			}
			uidOK = true
		}
		if strings.HasPrefix(line, "Gid:") {
			got := strings.TrimSpace(strings.TrimPrefix(line, "Gid:"))
			if got != wantG {
				return fmt.Errorf("gid mismatch: got %q, want %q", got, wantG)
			}
			gidOK = true
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scanning /proc/self/status: %w", err)
	}
	if !uidOK {
		return fmt.Errorf("Uid line not found in /proc/self/status")
	}
	if !gidOK {
		return fmt.Errorf("Gid line not found in /proc/self/status")
	}
	return nil
}

// clearAllCaps calls capset with a version-3 header and zeroed data, dropping
// all permitted, effective, and inheritable capability sets. This ensures the
// process cannot re-acquire privilege even if it manages to exec a binary with
// file capabilities.
func clearAllCaps() error {
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0, // 0 means current process
	}
	data := [2]unix.CapUserData{} // all fields zero → all caps cleared
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

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

// execTarget looks up TARGET in PATH and replaces the current process via execve.
func execTarget(argv []string, env []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("lookpath %s: %w", argv[0], err)
	}
	return unix.Exec(path, argv, env)
}
