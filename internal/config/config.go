// Package config loads and validates the optional ~/.byn/config file
// (TOML, no extension). It is the single source of truth for settings
// shared by the daemon and CLI — starting with the local browser admin
// portal's port. A missing file is valid and yields Default().
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Filename is the config file name inside the data dir. It has no extension
// (TOML inside) to match byn's other on-disk files.
const Filename = "config"

// DefaultUIPort is the default port for the local browser admin portal.
// 2967 = B-Y-N-S on a phone keypad — the Postgres/RabbitMQ-style fixed
// default. Overridable via [ui] port.
const DefaultUIPort = 2967

// DefaultIdleTimeout is how long a vault stays unlocked without activity
// before the daemon re-locks it (zeroes the in-memory key). Overridable
// via [daemon] idle_timeout; "0s" disables auto-relock.
const DefaultIdleTimeout = 15 * time.Minute

// DefaultSessionTTL is the default absolute lifetime of a minted session.
// After this period the session is revoked regardless of activity.
const DefaultSessionTTL = 12 * time.Hour

// DefaultRevealHideAfter is how long the browser portal shows a revealed
// secret value before re-masking it. Overridable via [ui] reveal_hide_after;
// "0s" keeps values shown until manually hidden. Display-only (browser-side);
// the daemon stores and serves it but does not act on it.
const DefaultRevealHideAfter = 15 * time.Second

// Duration is a time.Duration that decodes from a TOML duration string
// such as "15m" or "0s" (Go's time.ParseDuration syntax).
type Duration time.Duration

// UnmarshalText parses a TOML string into a Duration.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// MarshalText renders the Duration as a Go duration string.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Config is the parsed ~/.byn/config. Use Default() for the baseline and
// Load() to read from disk; the Go zero value is not a valid config.
type Config struct {
	UI       UI       `toml:"ui"`
	Daemon   Daemon   `toml:"daemon"`
	Security Security `toml:"security"`
}

// UI configures the local browser admin portal (Phase 2). Port is read
// from the data dir's config, so a future multi-instance layout can serve
// a distinct port without colliding.
type UI struct {
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
	// RevealHideAfter is how long the portal shows a revealed secret value
	// before re-masking it. "0s" keeps it shown until manually hidden.
	// Browser-side display behavior only — the daemon serves it, never acts.
	RevealHideAfter Duration `toml:"reveal_hide_after"`
}

// Daemon configures daemon-wide behavior.
type Daemon struct {
	// IdleTimeout re-locks an unlocked vault after this much inactivity.
	// 0 disables auto-relock.
	IdleTimeout Duration `toml:"idle_timeout"`
}

// Security configures the NU-track per-action authorization gates.
type Security struct {
	// SessionTTL is the absolute lifetime of a minted session (from creation
	// time). 0 disables the absolute-TTL check (sessions are bounded only by
	// the idle window and explicit lock/end calls). Default: 12h.
	SessionTTL Duration `toml:"session_ttl"`

	// SessionIdle is the sliding idle window for a session. A session that
	// has not been validated within this window expires. 0 (default) inherits
	// [daemon] idle_timeout — set the daemon's idle timeout to also bound
	// session idle time without repeating the value. Use "0s" explicitly to
	// disable idle expiry for sessions while keeping the vault idle timeout.
	SessionIdle Duration `toml:"session_idle"`

	// Privsep opts the daemon into running trusted-.byn `byn exec` children
	// SERVER-side under privilege separation (the _byn-exec service user),
	// instead of in-process as the owner. It is presence-detecting: a nil
	// pointer (key absent) means OFF — the conservative default while privsep
	// is still rolling out. Set `privsep = true` to enable, `false` to keep it
	// explicitly off. Enabling it requires `byn setup` to have provisioned the
	// service users; otherwise exec.spawn returns an actionable not-provisioned
	// error rather than silently falling back to an owner-UID spawn.
	Privsep *bool `toml:"privsep"`
}

// Default returns the built-in defaults, applied when the file is absent
// or a key is omitted.
func Default() Config {
	return Config{
		UI:     UI{Enabled: true, Port: DefaultUIPort, RevealHideAfter: Duration(DefaultRevealHideAfter)},
		Daemon: Daemon{IdleTimeout: Duration(DefaultIdleTimeout)},
		Security: Security{
			SessionTTL:  Duration(DefaultSessionTTL),
			SessionIdle: 0, // 0 ⇒ inherit [daemon] idle_timeout at runtime
		},
	}
}

// PrivsepEnabled reports whether [security] privsep is set to true. A nil
// pointer (key absent) OR an explicit false both yield false — privsep is
// off unless the config opts in. Folding the nil/false cases into one helper
// keeps every consumer (the daemon wiring, the CLI exec routing) reading the
// same single source of truth.
func (c Config) PrivsepEnabled() bool {
	return c.Security.Privsep != nil && *c.Security.Privsep
}

// Path returns the config file path for a given data dir.
func Path(dir string) string {
	return filepath.Join(dir, Filename)
}

// Parse decodes and validates a config from raw bytes (no disk access).
// It is used by config.set to validate the new content before writing it to
// disk. Returns the parsed Config or a validation error.
func Parse(content []byte) (Config, error) {
	cfg := Default()
	dec := toml.NewDecoder(strings.NewReader(string(content))).DisallowUnknownFields()
	if derr := dec.Decode(&cfg); derr != nil {
		return Config{}, derr
	}
	if verr := cfg.validate(); verr != nil {
		return Config{}, verr
	}
	return cfg, nil
}

// Load reads and validates the config at path. A missing file is not an
// error — it yields Default(). Present keys override the matching
// defaults; omitted keys keep them. Unknown keys and out-of-range values
// are rejected with an error that names the offending file.
func Load(path string) (Config, error) {
	cfg := Default()
	body, err := os.ReadFile(path) // #nosec G304 -- caller-resolved config path
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	dec := toml.NewDecoder(strings.NewReader(string(body))).DisallowUnknownFields()
	if derr := dec.Decode(&cfg); derr != nil {
		return Config{}, fmt.Errorf("%s: %w", path, derr)
	}
	if verr := cfg.validate(); verr != nil {
		return Config{}, fmt.Errorf("%s: %w", path, verr)
	}
	return cfg, nil
}

// validate enforces value-range invariants after decoding.
func (c Config) validate() error {
	if c.UI.Port < 1 || c.UI.Port > 65535 {
		return fmt.Errorf("ui.port %d out of range (must be 1-65535)", c.UI.Port)
	}
	if time.Duration(c.Daemon.IdleTimeout) < 0 {
		return fmt.Errorf("daemon.idle_timeout %v must not be negative (use \"0s\" to disable)",
			time.Duration(c.Daemon.IdleTimeout))
	}
	if time.Duration(c.UI.RevealHideAfter) < 0 {
		return fmt.Errorf("ui.reveal_hide_after %v must not be negative (use \"0s\" to disable auto-hide)",
			time.Duration(c.UI.RevealHideAfter))
	}
	return nil
}
