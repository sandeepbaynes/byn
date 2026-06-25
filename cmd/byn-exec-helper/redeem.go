package main

import (
	"fmt"
	"io"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/paths"
)

// redeemFlag is the sentinel that selects token-redemption mode (Option A,
// Terminal-anchored exec) instead of the legacy server-side `-- TARGET` mode.
const redeemFlag = "--redeem"

// sandboxExecPath is the macOS Seatbelt entrypoint. Only used when the daemon
// returns a non-empty profile (darwin); on other platforms the profile is always
// empty so this is never referenced.
const sandboxExecPath = "/usr/bin/sandbox-exec"

// redeemRequested reports whether the helper was invoked in token-redemption
// mode (the CLI passes redeemFlag; the token arrives on fd 3, not argv).
func redeemRequested(args []string) bool {
	for _, a := range args {
		if a == redeemFlag {
			return true
		}
	}
	return false
}

// readTokenFD reads the one-time exec token the CLI wrote to the given fd (3 by
// convention). The token is raw bytes terminated by EOF (the CLI closes the
// write end). It is never on argv (argv is world-readable).
func readTokenFD(fd uintptr) ([]byte, error) {
	f := os.NewFile(fd, "token-pipe")
	if f == nil {
		return nil, fmt.Errorf("fd %d is not valid", fd)
	}
	defer f.Close() //nolint:errcheck // read-only; close error is inconsequential
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading token fd: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty token on fd %d", fd)
	}
	return data, nil
}

// redeemSocketPath resolves the daemon socket from the TRUSTED paths package —
// NOT from any caller-supplied argument. Connecting to an attacker-chosen socket
// would leak the token (which could then be replayed against the real daemon), so
// the path must come from the fixed, system-resolved location only.
func redeemSocketPath() (string, error) {
	dir, err := paths.DataDir()
	if err != nil {
		return "", err
	}
	return paths.ActiveSocketPath(dir)
}

// redeemToken exchanges the one-time token with the daemon for the authorized
// child argv, the complete curated env, and the sandbox profile. The helper calls
// this after dropping to _byn-exec; the daemon's peercred gate accepts
// root/_byn-exec only.
func redeemToken(sock string, token []byte) (argv, env []string, profile string, err error) {
	client := ipc.NewClient(sock)
	var resp ipc.ExecRedeemResp
	if e := client.Call(ipc.OpExecRedeem, ipc.ExecRedeemReq{Token: token}, &resp); e != nil {
		return nil, nil, "", e
	}
	return resp.Argv, resp.Env, resp.SandboxProfile, nil
}

// buildExecArgv wraps argv in `sandbox-exec -p <profile>` when a profile is
// present (macOS), so Seatbelt is applied AFTER the privilege drop (the daemon
// already proved this preserves TCC inheritance). An empty profile (other
// platforms, or nothing to confine) runs the target directly.
func buildExecArgv(profile string, argv []string) []string {
	if profile == "" {
		return argv
	}
	out := make([]string, 0, len(argv)+3)
	out = append(out, sandboxExecPath, "-p", profile)
	out = append(out, argv...)
	return out
}

// redeemMain is the Option-A entrypoint: read the token (fd 3), drop to
// _byn-exec, redeem the token with the daemon, then exec the authorized target
// (sandbox-wrapped on macOS) with the curated env. The child is born in the
// invoking shell's process tree (the CLI spawned this helper), so it inherits the
// shell's TCC grant while running as _byn-exec.
//
// Drop order: the privilege drop happens BEFORE the daemon round-trip.
// On macOS the binary is setuid-root (euid=0); on Linux it has file capabilities
// (cap_setuid,cap_setgid+ep) and starts as the owner UID. In both cases, dropping
// to _byn-exec first is correct: the daemon's peercred gate accepts root/_byn-exec
// for exec.redeem, and _byn-exec satisfies that check. The sandbox profile (returned
// by redeemToken) is applied AFTER the drop (macOS refuses exec of a setuid binary
// while sandboxed).
func redeemMain() {
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

	token, err := readTokenFD(3)
	if err != nil {
		fatal("reading exec token: %v", err)
	}

	sock, err := redeemSocketPath()
	if err != nil {
		fatal("resolving daemon socket: %v", err)
	}

	// Drop to _byn-exec BEFORE connecting to the daemon. On macOS the binary is
	// setuid-root so this drops from root; on Linux the binary has file capabilities
	// and starts as the owner UID so this is the privilege escalation step. Either
	// way the daemon's peercred gate sees _byn-exec (an accepted helper identity).
	if err := dropTo(uid, gid); err != nil {
		fatal("dropping privileges: %v", err)
	}

	argv, childEnv, profile, rerr := redeemToken(sock, token)
	for i := range token { // zero the token after the round-trip
		token[i] = 0
	}
	if rerr != nil {
		fatal("redeeming exec token: %v", rerr)
	}
	if len(argv) == 0 {
		fatal("daemon returned no command to exec")
	}

	execArgv := buildExecArgv(profile, argv)
	if err := execTarget(execArgv, childEnv); err != nil {
		fatal("exec %s: %v", execArgv[0], err)
	}
}
