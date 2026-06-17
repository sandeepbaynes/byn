//go:build darwin

package privsep

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config configures a Spawner.
type Config struct {
	// HelperPath is the absolute path to the installed byn-exec-helper binary
	// (see HelperDestPath()). On Darwin the helper must be setuid-root
	// (macOS has no file capabilities) so it can drop the child to ExecUID/ExecGID.
	HelperPath string

	// Exec holds the resolved _byn-exec uid/gid (from LookupState).
	Exec State

	// StateDir is byn's data dir (the daemon owner's ~/.byn in NU-5). The Seatbelt
	// profile denies the exec child ALL access to it. Empty disables the deny.
	StateDir string

	// SocketPath is the daemon's Unix socket. The Seatbelt profile denies the
	// exec child file + network access to it. Empty disables the deny.
	SocketPath string
}

// SpawnReq describes a single child-process spawn request.
type SpawnReq struct {
	// Argv is [absTarget, args...]. argv[0] MUST be an absolute path; the helper
	// does no PATH lookup and rejects relative targets. The Spawner enforces this
	// too (defence-in-depth).
	Argv []string

	// Env is the COMPLETE child environment as KEY=VALUE strings. It is written
	// verbatim to fd 3 (NUL-delimited) and the helper sets the child's env to
	// exactly this — it does NOT merge its own environment.
	Env []string

	// Stdin, Stdout, Stderr are the raw fd numbers for the child's stdio.
	Stdin, Stdout, Stderr int

	// NoNetwork tightens the Seatbelt profile for this one action: deny all
	// network. Default false (most approved actions need the network).
	NoNetwork bool
}

// Spawner spawns exec children via the privileged byn-exec-helper.
type Spawner interface {
	// Spawn runs the child described by req and returns its exit code.
	// A non-zero exit code from the child is NOT an error — the caller
	// decides what to do with it. Only spawn-level failures (helper not
	// found, fd setup, etc.) return a non-nil error.
	Spawn(req SpawnReq) (exitCode int, err error)
}

// darwinSpawner is the Darwin implementation of Spawner.
type darwinSpawner struct {
	cfg Config
}

// NewSpawner returns a Spawner that delegates execution to the privileged
// helper at cfg.HelperPath.
//
// Task 7: the helper is wrapped in sandbox-exec (Seatbelt) — see Spawn. The
// _byn-exec UID boundary remains the load-bearing control; the Seatbelt profile
// is defense in depth that denies the child byn's own state dir + socket.
func NewSpawner(cfg Config) Spawner {
	return &darwinSpawner{cfg: cfg}
}

// Spawn implements Spawner for Darwin.
//
// Security properties:
//   - argv[0] must be absolute (enforced here AND by the helper — defence in depth).
//   - The child's full environment is passed via fd 3 as NUL-delimited KEY=VALUE
//     pairs; the helper installs exactly that env in the child, never merging its
//     own environment.
//   - Go's exec.Cmd sets O_CLOEXEC on all fds not in Stdin/Stdout/Stderr/ExtraFiles,
//     so the daemon's open socket, DB fds, etc. do NOT leak into the helper or child.
//   - The helper's own cmd.Env is set to nil (empty) — nothing leaks from the daemon
//     environment into the helper process itself; the child env comes via fd 3 only.
func (s *darwinSpawner) Spawn(req SpawnReq) (int, error) {
	if len(req.Argv) == 0 {
		return -1, errors.New("privsep: Spawn: argv is empty")
	}
	if !filepath.IsAbs(req.Argv[0]) {
		return -1, fmt.Errorf("privsep: Spawn: argv[0] %q is not an absolute path (resolve via exec.LookPath before calling Spawn)", req.Argv[0])
	}

	// Reject any env entry that contains a NUL byte — a NUL inside a value
	// would corrupt the NUL-delimited fd-3 framing read by the helper.
	for _, kv := range req.Env {
		if strings.IndexByte(kv, 0) >= 0 {
			return -1, fmt.Errorf("privsep: env entry contains NUL byte")
		}
	}

	// Create a pipe for the child environment. The write end is closed once all
	// KEY=VALUE\0 pairs have been written (done in a goroutine to avoid deadlock
	// when the env is large enough to fill the pipe buffer before the helper
	// reads). The read end becomes fd 3 in the helper via ExtraFiles.
	envR, envW, err := os.Pipe()
	if err != nil {
		return -1, fmt.Errorf("privsep: Spawn: create env pipe: %w", err)
	}

	go func() {
		defer func() { _ = envW.Close() }()
		for _, kv := range req.Env {
			// NUL-delimited: KEY=VALUE\x00
			if _, werr := envW.WriteString(kv + "\x00"); werr != nil {
				// The helper closed its read end early (or died). Nothing more
				// to write — exit the goroutine without crashing the daemon.
				return
			}
		}
	}()

	// Build the helper invocation: <helperPath> -- <absTarget> [args...]
	// Task 7: wrap the helper in sandbox-exec (Seatbelt). The sandbox is inherited
	// across the helper's drop-privs + exec, so the child runs sandboxed as
	// _byn-exec. The setuid helper itself runs under the sandbox too.
	helperArgs := append([]string{"--"}, req.Argv...)
	cmd, cleanupProfile, perr := s.sandboxCommand(req, helperArgs)
	if perr != nil {
		_ = envR.Close()
		return -1, perr
	}
	defer cleanupProfile()

	// Dup the caller's stdio fds so cmd owns separate fds; the daemon's
	// req.Stdin/out/err are never closed by the Spawner.
	stdinFile, stdoutFile, stderrFile, err := dupStdio(req)
	if err != nil {
		_ = envR.Close()
		return -1, err
	}
	defer func() {
		_ = stdinFile.Close()
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
	}()
	cmd.Stdin = stdinFile
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	// ExtraFiles[0] → fd 3 in the helper (Go guarantees: fd 3+i for ExtraFiles[i]).
	// Only the env pipe is added — no other daemon fds must appear here.
	// All other daemon fds are O_CLOEXEC (Go sets this on all fds it opens) and
	// will be closed automatically across the exec boundary.
	cmd.ExtraFiles = []*os.File{envR}

	// The helper reads the child env from fd 3; its own process environment is
	// irrelevant and must not leak daemon secrets. Set it to empty.
	cmd.Env = []string{}

	runErr := cmd.Run()

	// Close the read end after the helper exits (or fails to start).
	// The goroutine already closed the write end.
	_ = envR.Close()

	if runErr == nil {
		return 0, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		// Child exited with a non-zero code — this is the child's own exit status,
		// not a spawn failure. Return it to the caller; nil error signals clean spawn.
		return exitErr.ExitCode(), nil
	}

	// Any other error means the helper itself failed to start or was killed by a
	// signal without an exit code.
	return -1, fmt.Errorf("privsep: Spawn: helper failed: %w", runErr)
}

// sandbox-exec is the macOS Seatbelt entrypoint. Deprecated-but-ubiquitous
// (Chromium/Bazel use it; works on Sonoma/Sequoia).
const sandboxExecPath = "/usr/bin/sandbox-exec"

// sandboxCommand builds the *exec.Cmd that runs the helper. When there is
// something to confine (state dir, socket, or NoNetwork), the helper is wrapped
// in sandbox-exec with a generated SBPL profile written to a temp file; the
// returned cleanup removes that file. Otherwise the helper runs directly and
// cleanup is a no-op.
//
// IMPORTANT (Seatbelt path matching): Seatbelt matches the kernel-RESOLVED,
// symlink-free real path. A deny on e.g. /tmp/x fails to match if /tmp is a
// symlink (it is, → /private/tmp). We therefore EvalSymlinks the paths before
// embedding them so the deny actually bites. If a path can't be resolved
// (doesn't exist yet) we fall back to the raw path — better an over-broad-but-
// harmless deny than a silently no-op one; the UID boundary still holds either way.
func (s *darwinSpawner) sandboxCommand(req SpawnReq, helperArgs []string) (*exec.Cmd, func(), error) {
	noop := func() {}

	stateDir := resolveSymlinks(s.cfg.StateDir)
	socketPath := resolveSymlinks(s.cfg.SocketPath)

	// Nothing to confine → run the helper directly (skip sandbox-exec). We still
	// prefer wrapping whenever any deny is requested, for consistency.
	if stateDir == "" && socketPath == "" && !req.NoNetwork {
		return exec.Command(s.cfg.HelperPath, helperArgs...), noop, nil //nolint:gosec // HelperPath is operator-installed
	}

	profile := seatbeltProfile(SandboxOpts{
		StateDir:   stateDir,
		SocketPath: socketPath,
		NoNetwork:  req.NoNetwork,
	})

	f, err := os.CreateTemp(os.TempDir(), "byn-sb-*.sb")
	if err != nil {
		return nil, noop, fmt.Errorf("privsep: Spawn: create sandbox profile: %w", err)
	}
	cleanup := func() { _ = os.Remove(f.Name()) }
	if cerr := f.Chmod(0o600); cerr != nil {
		_ = f.Close()
		cleanup()
		return nil, noop, fmt.Errorf("privsep: Spawn: chmod sandbox profile: %w", cerr)
	}
	if _, werr := f.WriteString(profile); werr != nil {
		_ = f.Close()
		cleanup()
		return nil, noop, fmt.Errorf("privsep: Spawn: write sandbox profile: %w", werr)
	}
	if cerr := f.Close(); cerr != nil {
		cleanup()
		return nil, noop, fmt.Errorf("privsep: Spawn: close sandbox profile: %w", cerr)
	}

	// <helperPath> -- sandbox-exec -f <profile> <absTarget> [args...]
	//
	// We run the SETUID helper DIRECTLY (no outer sandbox). It drops to
	// _byn-exec, then execs sandbox-exec on the NON-setuid target, so the sandbox
	// is applied AFTER the privilege drop. macOS REFUSES to exec a setuid binary
	// while sandboxed (a privilege-escalation guard): wrapping the setuid helper
	// in sandbox-exec failed with "execvp() ... Operation not permitted".
	// Sandboxing the target (not the helper) is the supported order; the small,
	// trusted helper runs briefly unsandboxed only to perform the drop. The
	// curated child env (fd 3) is inherited through sandbox-exec to the target.
	hargs := append([]string{"--", sandboxExecPath, "-f", f.Name()}, req.Argv...)
	return exec.Command(s.cfg.HelperPath, hargs...), cleanup, nil //nolint:gosec // operator-installed helper, generated profile
}

// resolveSymlinks returns the symlink-free real path for p, or p unchanged if it
// is empty or cannot be resolved (e.g. it does not exist yet). See the Seatbelt
// path-matching note on sandboxCommand for why this matters.
func resolveSymlinks(p string) string {
	if p == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	return p
}
