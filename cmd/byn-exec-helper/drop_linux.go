//go:build linux

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// helperConfigPath is the compiled-in path of the root-owned UID/GID config. It
// lives beside the helper binary in the root-owned /usr/local/libexec, NOT in the
// _byn-owned /var/lib/byn state dir, so the daemon user cannot rewrite it, the
// "all parent dirs root-owned" invariant holds, and it does not collide with
// `byn migrate`. MUST match helperConfigPathLinux in
// internal/privsep/provision_linux.go EXACTLY.
const helperConfigPath = "/usr/local/libexec/byn-exec-helper.conf"

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

	// 6. Mark the child undumpable BEFORE execve. After the drop the child runs
	//    as _byn-exec; a SAME-UID _byn-exec peer could otherwise read this
	//    child's /proc/<pid>/environ and harvest its injected secrets. With
	//    dumpable=0 the kernel reparents /proc/<pid>/* to root:root, so only
	//    root can read it, and core dumps are disabled (a crash can't spill the
	//    injected env to disk). Consistent with the helper's all-or-nothing
	//    hardening: lowering one's own dumpable flag never requires privilege,
	//    so a failure here is anomalous — abort rather than exec a child with a
	//    weaker posture than promised. The dumpable flag is preserved across
	//    execve when the new image is a non-suid binary (the daemon resolves an
	//    ordinary target), so the executed child stays undumpable.
	if err := setUndumpable(); err != nil {
		return fmt.Errorf("setting undumpable: %w", err)
	}

	return nil
}

// setUndumpable clears the process dumpable flag via prctl(PR_SET_DUMPABLE, 0)
// so a same-UID peer cannot read this process's /proc/<pid>/{mem,environ,…} and
// so a crash cannot core-dump the injected secrets. Best-effort hardening on
// top of the UID boundary; it does not defend against root.
func setUndumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", err)
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
		return fmt.Errorf("uid line not found in /proc/self/status")
	}
	if !gidOK {
		return fmt.Errorf("gid line not found in /proc/self/status")
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

// execTarget replaces the current process via execve. It requires an ABSOLUTE
// target path and does NO PATH resolution — the daemon resolves PATH itself,
// unprivileged, removing the PATH-poisoning vector from the privileged helper.
func execTarget(argv []string, env []string) error {
	if !filepath.IsAbs(argv[0]) {
		return fmt.Errorf("target %q is not an absolute path", argv[0])
	}
	return unix.Exec(argv[0], argv, env)
}
