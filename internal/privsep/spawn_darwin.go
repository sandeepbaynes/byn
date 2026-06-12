//go:build darwin

package privsep

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Config configures a Spawner.
type Config struct {
	// HelperPath is the absolute path to the installed byn-exec-helper binary
	// (see HelperDestPath()). On Darwin the helper must be setuid-root
	// (macOS has no file capabilities) so it can drop the child to ExecUID/ExecGID.
	HelperPath string

	// Exec holds the resolved _byn-exec uid/gid (from LookupState).
	Exec State
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
// Task 7: sandbox wrapper hook — to add Seatbelt (sandbox-exec -f <profile>),
// wrap the cfg.HelperPath invocation here: replace the exec.Command target with
// "sandbox-exec" and prepend ["-f", profilePath, cfg.HelperPath] to helperArgs.
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
	// Task 7: sandbox wrapper hook — insert sandbox-exec preamble here if needed.
	helperArgs := append([]string{"--"}, req.Argv...)
	cmd := exec.Command(s.cfg.HelperPath, helperArgs...) //nolint:gosec // HelperPath is operator-installed

	// Wire the child stdio to the caller-supplied fds.
	// os.NewFile does NOT take ownership; we do NOT close these fds here —
	// the caller manages their lifetime.
	cmd.Stdin = os.NewFile(uintptr(req.Stdin), "stdin")
	cmd.Stdout = os.NewFile(uintptr(req.Stdout), "stdout")
	cmd.Stderr = os.NewFile(uintptr(req.Stderr), "stderr")

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
