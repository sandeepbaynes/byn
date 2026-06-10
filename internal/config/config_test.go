package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// writeConfig writes contents to a config file in a fresh temp dir and
// returns its path.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), Filename)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestDefault(t *testing.T) {
	d := Default()
	if !d.UI.Enabled {
		t.Errorf("Default().UI.Enabled = false, want true")
	}
	if d.UI.Port != DefaultUIPort {
		t.Errorf("Default().UI.Port = %d, want %d", d.UI.Port, DefaultUIPort)
	}
	if DefaultUIPort != 2967 {
		t.Errorf("DefaultUIPort = %d, want 2967 (B-Y-N-S on a phone keypad)", DefaultUIPort)
	}
	if got := time.Duration(d.Daemon.IdleTimeout); got != DefaultIdleTimeout {
		t.Errorf("Default().Daemon.IdleTimeout = %v, want %v", got, DefaultIdleTimeout)
	}
	if DefaultIdleTimeout != 15*time.Minute {
		t.Errorf("DefaultIdleTimeout = %v, want 15m", DefaultIdleTimeout)
	}
}

func TestLoad_IdleTimeout_Set(t *testing.T) {
	path := writeConfig(t, "[daemon]\nidle_timeout = \"5m\"\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.Daemon.IdleTimeout); d != 5*time.Minute {
		t.Errorf("Daemon.IdleTimeout = %v, want 5m", d)
	}
	// [ui] untouched → defaults preserved.
	if got.UI.Port != DefaultUIPort {
		t.Errorf("UI.Port = %d, want default %d", got.UI.Port, DefaultUIPort)
	}
}

func TestLoad_IdleTimeout_ZeroDisables(t *testing.T) {
	path := writeConfig(t, "[daemon]\nidle_timeout = \"0s\"\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.Daemon.IdleTimeout); d != 0 {
		t.Errorf("Daemon.IdleTimeout = %v, want 0 (disabled)", d)
	}
}

func TestLoad_IdleTimeout_DefaultPreservedWhenOmitted(t *testing.T) {
	// A [daemon] section with no idle_timeout keeps the default.
	path := writeConfig(t, "[daemon]\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.Daemon.IdleTimeout); d != DefaultIdleTimeout {
		t.Errorf("Daemon.IdleTimeout = %v, want default %v", d, DefaultIdleTimeout)
	}
}

func TestRoundTrip_MarshalThenLoad(t *testing.T) {
	// A non-default config marshalled to TOML and reloaded must compare
	// equal — exercises Duration.MarshalText and the decode path together.
	want := Config{
		UI:       UI{Enabled: false, Port: 8080},
		Daemon:   Daemon{IdleTimeout: Duration(30 * time.Minute)},
		Security: Security{PerActionAuth: true},
	}
	out, err := toml.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := writeConfig(t, string(out))
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Errorf("round-trip = %+v, want %+v (TOML was:\n%s)", got, want, out)
	}
}

func TestLoad_IdleTimeout_BadDuration_Errors(t *testing.T) {
	path := writeConfig(t, "[daemon]\nidle_timeout = \"nonsense\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(bad idle_timeout) error = nil, want error")
	}
}

func TestLoad_IdleTimeout_Negative_Errors(t *testing.T) {
	path := writeConfig(t, "[daemon]\nidle_timeout = \"-5m\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(negative idle_timeout) error = nil, want error")
	}
}

func TestPath(t *testing.T) {
	got := Path(filepath.Join("/home", "u", ".byn"))
	want := filepath.Join("/home", "u", ".byn", "config")
	if got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestLoad_MissingFile_ReturnsDefaults(t *testing.T) {
	// A path inside a temp dir that was never created.
	path := filepath.Join(t.TempDir(), "does-not-exist", Filename)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(missing) error = %v, want nil", err)
	}
	if got != Default() {
		t.Errorf("Load(missing) = %+v, want Default() %+v", got, Default())
	}
}

func TestLoad_UnreadablePath_Errors(t *testing.T) {
	// A path that exists but is a directory, not a file: os.ReadFile
	// returns a non-ENOENT error, which must surface (not be treated as
	// "missing file → defaults").
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load(directory path) error = nil, want error")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not mention the path %q", err.Error(), dir)
	}
}

func TestLoad_EmptyFile_ReturnsDefaults(t *testing.T) {
	path := writeConfig(t, "")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load(empty) error = %v, want nil", err)
	}
	if got != Default() {
		t.Errorf("Load(empty) = %+v, want Default() %+v", got, Default())
	}
}

func TestLoad_FullConfig(t *testing.T) {
	path := writeConfig(t, "[ui]\nenabled = false\nport = 3000\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if got.UI.Enabled {
		t.Errorf("UI.Enabled = true, want false")
	}
	if got.UI.Port != 3000 {
		t.Errorf("UI.Port = %d, want 3000", got.UI.Port)
	}
}

func TestLoad_PartialConfig_KeepsDefaults(t *testing.T) {
	// Only port is set; enabled must retain its default (true).
	path := writeConfig(t, "[ui]\nport = 4000\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if !got.UI.Enabled {
		t.Errorf("UI.Enabled = false, want true (default preserved)")
	}
	if got.UI.Port != 4000 {
		t.Errorf("UI.Port = %d, want 4000", got.UI.Port)
	}
}

func TestLoad_UnknownTopLevelKey_Errors(t *testing.T) {
	path := writeConfig(t, "bogus = 1\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load(unknown top-level key) error = nil, want error")
	}
	// Error must point at the offending file so the user knows where to look.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not mention config path %q", err.Error(), path)
	}
}

func TestLoad_UnknownUIKey_Errors(t *testing.T) {
	path := writeConfig(t, "[ui]\nfoo = 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(unknown [ui] key) error = nil, want error")
	}
}

func TestLoad_MalformedTOML_Errors(t *testing.T) {
	path := writeConfig(t, "[ui\nport = 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(malformed TOML) error = nil, want error")
	}
}

func TestLoad_WrongType_Errors(t *testing.T) {
	path := writeConfig(t, "[ui]\nport = \"nope\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(port as string) error = nil, want error")
	}
}

func TestSecurityPerActionAuthDefaultsFalse(t *testing.T) {
	cfg := Default()
	if cfg.Security.PerActionAuth {
		t.Errorf("Default().Security.PerActionAuth = true, want false")
	}
}

func TestSecurityPerActionAuthLoads(t *testing.T) {
	path := writeConfig(t, "[security]\nper_action_auth = true\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if !got.Security.PerActionAuth {
		t.Errorf("Security.PerActionAuth = false, want true")
	}
}

func TestSecuritySectionAbsentDefaultsFalse(t *testing.T) {
	// A config file without a [security] section should default to false.
	path := writeConfig(t, "[ui]\nenabled = true\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if got.Security.PerActionAuth {
		t.Errorf("Security.PerActionAuth = true, want false (absent section)")
	}
}

func TestLoad_UnknownSecurityKey_Errors(t *testing.T) {
	path := writeConfig(t, "[security]\nper_action_auth_x = 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(unknown [security] key) error = nil, want error")
	}
}

func TestLoad_SecurityPerActionAuth_WrongType_Errors(t *testing.T) {
	// per_action_auth must be a boolean; a string value must fail.
	path := writeConfig(t, "[security]\nper_action_auth = \"yes\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(per_action_auth as string) error = nil, want error")
	}
}

func TestLoad_PortRange(t *testing.T) {
	cases := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"one", 1, false},
		{"default", 2967, false},
		{"max", 65535, false},
		{"too-big", 65536, true},
		{"way-too-big", 99999, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, "[ui]\nport = "+itoa(tc.port)+"\n")
			_, err := Load(path)
			if tc.wantErr && err == nil {
				t.Errorf("port %d: error = nil, want error", tc.port)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("port %d: error = %v, want nil", tc.port, err)
			}
		})
	}
}

// itoa is a tiny local helper so the test file has no extra imports just
// for formatting an int into TOML.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
