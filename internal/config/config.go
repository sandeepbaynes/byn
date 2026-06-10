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

// Filename is the config file name inside $BYN_DIR. It has no extension
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
// per-$BYN_DIR, so multiple data dirs can each later serve their own
// portal on a distinct port without colliding.
type UI struct {
	Enabled bool `toml:"enabled"`
	Port    int  `toml:"port"`
}

// Daemon configures daemon-wide behavior.
type Daemon struct {
	// IdleTimeout re-locks an unlocked vault after this much inactivity.
	// 0 disables auto-relock.
	IdleTimeout Duration `toml:"idle_timeout"`
}

// Security configures the NU-track per-action authorization gates.
type Security struct {
	// PerActionAuth requires a fresh authorization (master password or a
	// one-time presence token) for get, overwrite-put, and delete EVEN
	// while the vault is unlocked. Opt-in until sessions (NU-3) restore
	// one-auth-per-session ergonomics. Trusted-.byn exec is unaffected:
	// the .byn is the authorization. Insert and list stay free.
	PerActionAuth bool `toml:"per_action_auth"`
}

// Default returns the built-in defaults, applied when the file is absent
// or a key is omitted.
func Default() Config {
	return Config{
		UI:       UI{Enabled: true, Port: DefaultUIPort},
		Daemon:   Daemon{IdleTimeout: Duration(DefaultIdleTimeout)},
		Security: Security{PerActionAuth: false},
	}
}

// Path returns the config file path for a given $BYN_DIR.
func Path(dir string) string {
	return filepath.Join(dir, Filename)
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
	return nil
}
