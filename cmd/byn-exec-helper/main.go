// Command byn-exec-helper is the privileged spawn helper for NU-5 exec-child
// privsep. Installed root-owned with file capabilities cap_setuid,cap_setgid+ep
// (Linux) or setuid-root (macOS); invoked ONLY by the byn daemon.
//
// Contract (the daemon sets this up before exec; the helper trusts NO external
// input — no flags, no env-derived behavior):
//   - argv: byn-exec-helper -- TARGET [ARGS...]   (after -- is the child)
//   - fd 3 carries the COMPLETE, NUL-delimited child environment (the daemon
//     builds it: owner's terminal env minus sensitive vars, plus injected
//     secrets). The helper sets the child env to EXACTLY this — it never leaks
//     its own process environment. Env is NEVER passed on argv (argv is
//     world-readable).
//   - the daemon MUST pass an ABSOLUTE target path (it resolves PATH itself,
//     unprivileged) — the helper does no PATH lookup.
//   - stdio fds 0/1/2 are already the owner's terminal fds (dup'd by the daemon).
//   - the target _byn-exec uid/gid are read at runtime from a root-owned,
//     root-only-writable config at a COMPILED-IN path (readTargetIDs), not from
//     argv/env (a caller cannot redirect which user we drop to).
//
// It drops privileges (setgroups → setresgid → setresuid → verify → clear caps),
// then execve's the target. Any failure → exit non-zero BEFORE exec; it never
// runs the target with undropped privilege.
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// helperConfigPath is the compiled-in, per-platform path of the root-owned
// config holding the target UID/GID — defined in drop_linux.go and
// drop_darwin.go. NEVER from argv/env.

// dropPlan returns the ordered syscall labels for the privilege drop. Pure
// function so the order is unit-testable without root. Panics on uid 0.
func dropPlan(uid, gid int) []string {
	if uid == 0 {
		panic("byn-exec-helper: refusing to drop to uid 0")
	}
	return []string{
		"setgroups[]",
		fmt.Sprintf("setresgid(%d,%d,%d)", gid, gid, gid),
		fmt.Sprintf("setresuid(%d,%d,%d)", uid, uid, uid),
		"verify",
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "byn-exec-helper: "+format+"\n", a...)
	os.Exit(127)
}

// readTargetIDs reads (uid,gid) from the root-owned helper config at the
// compiled-in helperConfigPath, refusing unless it is a regular file (not a
// symlink), owned by uid 0, and not writable by group/other. Content: two
// lines "<uid>\n<gid>\n". The ONLY source of the target IDs; not
// caller-influenceable (path is a constant; file is root-only-writable).
func readTargetIDs() (uid, gid int, err error) {
	// O_NOFOLLOW rejects a final-component symlink. NOTE: it only guards the
	// final component; intermediate-dir integrity relies on the installer making
	// all parent dirs root-owned (an install invariant — Task 4/5).
	f, err := os.OpenFile(helperConfigPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("open config %s: %w", helperConfigPath, err)
	}
	defer f.Close()     //nolint:errcheck // read-only fd; close error is inconsequential
	fi, err := f.Stat() // fstat on the OPEN fd — same object we read, no swap window
	if err != nil {
		return 0, 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, 0, fmt.Errorf("config %s is not a regular file", helperConfigPath)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 {
		return 0, 0, fmt.Errorf("config %s is not root-owned", helperConfigPath)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return 0, 0, fmt.Errorf("config %s is group/other-writable", helperConfigPath)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		return 0, 0, fmt.Errorf("config %s malformed", helperConfigPath)
	}
	if uid, err = strconv.Atoi(strings.TrimSpace(lines[0])); err != nil {
		return 0, 0, fmt.Errorf("config uid: %w", err)
	}
	if gid, err = strconv.Atoi(strings.TrimSpace(lines[1])); err != nil {
		return 0, 0, fmt.Errorf("config gid: %w", err)
	}
	return uid, gid, nil
}

func main() {
	// Option A (Terminal-anchored exec): the CLI invokes us with --redeem and the
	// one-time token on fd 3. We redeem it with the daemon for the authorized
	// argv+env, then drop + exec. The legacy server-side `-- TARGET` mode (the
	// daemon spawns us with the child env on fd 3) is kept for handleExecSpawn.
	if redeemRequested(os.Args) {
		redeemMain()
		return
	}
	legacyMain()
}

// legacyMain is the original server-side spawn contract (daemon → helper with
// `-- TARGET [ARGS]` and the child env on fd 3). Superseded by redeemMain for the
// owner-facing exec path; retained while handleExecSpawn exists.
func legacyMain() {
	uid, gid, err := readTargetIDs()
	if err != nil {
		fatal("reading target ids: %v", err)
	}
	if uid <= 0 || gid <= 0 {
		fatal("config has non-positive uid/gid (%d/%d)", uid, gid)
	}
	if uid == os.Getuid() {
		fatal("refusing: target uid %d equals caller uid", uid)
	}

	sep := -1
	for i, a := range os.Args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep+1 >= len(os.Args) {
		fatal("usage: byn-exec-helper -- TARGET [ARGS...]")
	}
	childArgv := os.Args[sep+1:]

	childEnv, err := readEnvFD(3)
	if err != nil {
		fatal("reading injected env: %v", err)
	}

	if err := dropTo(uid, gid); err != nil {
		fatal("dropping privileges: %v", err)
	}

	// fd 3 is the COMPLETE child environment the daemon curated; the helper
	// sets the child env to EXACTLY this and never leaks its own (daemon-
	// inherited) process environment.
	env := childEnv

	if err := execTarget(childArgv, env); err != nil {
		fatal("exec %s: %v", childArgv[0], err)
	}
}
