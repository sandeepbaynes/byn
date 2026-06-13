//go:build !linux && !darwin

package privsep

// Config configures a Spawner.
type Config struct {
	// HelperPath is the absolute path to the installed byn-exec-helper binary.
	HelperPath string

	// Exec holds the resolved _byn-exec uid/gid (from LookupState).
	Exec State

	// StateDir / SocketPath: byn's data dir and daemon socket. Unused on
	// unsupported platforms; present so Config is cross-platform.
	StateDir   string
	SocketPath string
}

// SpawnReq describes a single child-process spawn request.
type SpawnReq struct {
	// Argv is [absTarget, args...]. argv[0] MUST be an absolute path.
	Argv []string

	// Env is the COMPLETE child environment as KEY=VALUE strings.
	Env []string

	// Stdin, Stdout, Stderr are the raw fd numbers for the child's stdio.
	Stdin, Stdout, Stderr int

	// NoNetwork requests per-action network denial. Unsupported platforms have no
	// confinement mechanism; the field exists so SpawnReq is cross-platform.
	NoNetwork bool
}

// Spawner spawns exec children via the privileged byn-exec-helper.
type Spawner interface {
	// Spawn runs the child described by req and returns its exit code.
	// A non-zero exit code from the child is NOT an error.
	Spawn(req SpawnReq) (exitCode int, err error)
}

// unsupportedSpawner is a no-op Spawner for platforms without privsep support.
type unsupportedSpawner struct{}

// NewSpawner returns a Spawner that always returns ErrUnsupported on
// platforms where privilege separation is not implemented.
func NewSpawner(_ Config) Spawner {
	return &unsupportedSpawner{}
}

// Spawn always returns (-1, ErrUnsupported) on unsupported platforms.
func (u *unsupportedSpawner) Spawn(_ SpawnReq) (int, error) {
	return -1, ErrUnsupported
}
