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
	if got := time.Duration(d.UI.RevealHideAfter); got != DefaultRevealHideAfter {
		t.Errorf("Default().UI.RevealHideAfter = %v, want %v", got, DefaultRevealHideAfter)
	}
	if DefaultRevealHideAfter != 15*time.Second {
		t.Errorf("DefaultRevealHideAfter = %v, want 15s", DefaultRevealHideAfter)
	}
}

func TestLoad_RevealHideAfter_Set(t *testing.T) {
	path := writeConfig(t, "[ui]\nreveal_hide_after = \"30s\"\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.UI.RevealHideAfter); d != 30*time.Second {
		t.Errorf("UI.RevealHideAfter = %v, want 30s", d)
	}
}

func TestLoad_RevealHideAfter_ZeroDisablesAutoHide(t *testing.T) {
	path := writeConfig(t, "[ui]\nreveal_hide_after = \"0s\"\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.UI.RevealHideAfter); d != 0 {
		t.Errorf("UI.RevealHideAfter = %v, want 0 (auto-hide disabled)", d)
	}
}

func TestLoad_RevealHideAfter_DefaultPreservedWhenOmitted(t *testing.T) {
	// A [ui] section with no reveal_hide_after keeps the default.
	path := writeConfig(t, "[ui]\nport = 4000\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if d := time.Duration(got.UI.RevealHideAfter); d != DefaultRevealHideAfter {
		t.Errorf("UI.RevealHideAfter = %v, want default %v", d, DefaultRevealHideAfter)
	}
}

func TestLoad_RevealHideAfter_Negative_Errors(t *testing.T) {
	path := writeConfig(t, "[ui]\nreveal_hide_after = \"-5s\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(negative reveal_hide_after) error = nil, want error")
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
		UI:     UI{Enabled: false, Port: 8080},
		Daemon: Daemon{IdleTimeout: Duration(30 * time.Minute)},
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
	if got.UI != want.UI || got.Daemon != want.Daemon {
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

func TestLoad_UnknownSecurityKey_Errors(t *testing.T) {
	path := writeConfig(t, "[security]\nbogus_key = 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load(unknown [security] key) error = nil, want error")
	}
}

// TestLoad_PerActionAuth_UnknownKey verifies that per_action_auth is now fully
// removed: writing the key to the config file must be rejected as an unknown
// key by the strict parser — proving the flag never shipped and cannot be set.
func TestLoad_PerActionAuth_UnknownKey(t *testing.T) {
	// per_action_auth was removed; the strict parser must reject it.
	path := writeConfig(t, "[security]\nper_action_auth = true\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load(per_action_auth = true) error = nil, want error (unknown key)")
	}
	// The strict TOML parser returns "strict mode: fields in the document are
	// missing in the target struct" — it does not embed the field name.
	if !strings.Contains(err.Error(), "strict mode") && !strings.Contains(err.Error(), "unknown") {
		t.Errorf("error %q does not indicate a strict/unknown-key parse failure", err.Error())
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

// TestParse_ValidBytes verifies Parse accepts valid content and returns the
// parsed config.
func TestParse_ValidBytes(t *testing.T) {
	content := []byte("[ui]\nport = 3000\n")
	got, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse valid: %v", err)
	}
	if got.UI.Port != 3000 {
		t.Errorf("Parse: UI.Port = %d, want 3000", got.UI.Port)
	}
	// Defaults are preserved for omitted keys.
	if !got.UI.Enabled {
		t.Errorf("Parse: UI.Enabled = false, want true (default preserved)")
	}
}

// TestParse_BadTOML verifies Parse rejects bad TOML.
func TestParse_BadTOML(t *testing.T) {
	_, err := Parse([]byte("not toml [[["))
	if err == nil {
		t.Fatal("Parse(bad TOML) error = nil, want error")
	}
}

// TestParse_OutOfRange verifies Parse rejects out-of-range values.
func TestParse_OutOfRange(t *testing.T) {
	_, err := Parse([]byte("[ui]\nport = 99999\n"))
	if err == nil {
		t.Fatal("Parse(out-of-range port) error = nil, want error")
	}
}

// TestParse_UnknownKey verifies Parse rejects unknown keys.
func TestParse_UnknownKey(t *testing.T) {
	_, err := Parse([]byte("bogus = 1\n"))
	if err == nil {
		t.Fatal("Parse(unknown key) error = nil, want error")
	}
}

// TestParse_EmptyBytes returns defaults (same as missing file via Load).
func TestParse_EmptyBytes(t *testing.T) {
	got, err := Parse([]byte{})
	if err != nil {
		t.Fatalf("Parse(empty): %v", err)
	}
	if got != Default() {
		t.Errorf("Parse(empty) = %+v, want Default() %+v", got, Default())
	}
}

// TestSerializeCfgDefaultForm feeds the EXACT string that the JS serializeCfg
// function produces for the default form values into config.Parse. This guards
// against serializer drift: if serializeCfg changes its output shape or
// escaping, the test must be updated in sync.
//
// Keep these default values in sync with the comment above serializeCfg in
// internal/ui/assets/app.js:
//
//	uiEnabled=true, uiPort=2967, revealHideAfter="15s", idleTimeout="15m0s"
func TestSerializeCfgDefaultForm(t *testing.T) {
	// This is the verbatim output of serializeCfg({
	//   uiEnabled:true, uiPort:2967, revealHideAfter:"15s", idleTimeout:"15m0s"
	// }) as of the last sync with app.js.
	jsSerialized := "[ui]\nenabled = true\nport    = 2967\nreveal_hide_after = \"15s\"\n\n[daemon]\nidle_timeout = \"15m0s\"\n\n"

	got, err := Parse([]byte(jsSerialized))
	if err != nil {
		t.Fatalf("Parse(JS default form output): %v\nInput was:\n%s", err, jsSerialized)
	}
	if !got.UI.Enabled {
		t.Errorf("UI.Enabled = false, want true")
	}
	if got.UI.Port != DefaultUIPort {
		t.Errorf("UI.Port = %d, want %d", got.UI.Port, DefaultUIPort)
	}
	if time.Duration(got.UI.RevealHideAfter) != DefaultRevealHideAfter {
		t.Errorf("UI.RevealHideAfter = %v, want %v", time.Duration(got.UI.RevealHideAfter), DefaultRevealHideAfter)
	}
	if time.Duration(got.Daemon.IdleTimeout) != DefaultIdleTimeout {
		t.Errorf("Daemon.IdleTimeout = %v, want %v", time.Duration(got.Daemon.IdleTimeout), DefaultIdleTimeout)
	}
}

// TestLoad_Privsep_Absent verifies that omitting [security] privsep leaves the
// pointer nil and PrivsepEnabled() false — the conservative OFF default.
func TestLoad_Privsep_Absent(t *testing.T) {
	path := writeConfig(t, "")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Security.Privsep != nil {
		t.Errorf("Privsep = %v, want nil (absent)", *got.Security.Privsep)
	}
	if got.PrivsepEnabled() {
		t.Error("PrivsepEnabled() = true, want false when absent")
	}
}

// TestLoad_Privsep_True verifies that privsep = true is detected as ON.
func TestLoad_Privsep_True(t *testing.T) {
	path := writeConfig(t, "[security]\nprivsep = true\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Security.Privsep == nil || !*got.Security.Privsep {
		t.Fatalf("Privsep = %v, want non-nil true", got.Security.Privsep)
	}
	if !got.PrivsepEnabled() {
		t.Error("PrivsepEnabled() = false, want true when privsep = true")
	}
}

// TestLoad_Privsep_False verifies that privsep = false is detected as OFF
// (present but explicitly disabled) — distinct from absent at the pointer
// level, identical at the PrivsepEnabled() boundary.
func TestLoad_Privsep_False(t *testing.T) {
	path := writeConfig(t, "[security]\nprivsep = false\n")
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Security.Privsep == nil || *got.Security.Privsep {
		t.Fatalf("Privsep = %v, want non-nil false", got.Security.Privsep)
	}
	if got.PrivsepEnabled() {
		t.Error("PrivsepEnabled() = true, want false when privsep = false")
	}
}

// TestDefault_PrivsepOff verifies the built-in Default() leaves privsep off.
func TestDefault_PrivsepOff(t *testing.T) {
	if Default().PrivsepEnabled() {
		t.Error("Default().PrivsepEnabled() = true, want false")
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
