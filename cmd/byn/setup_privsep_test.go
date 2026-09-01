package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/config"
)

func readCfg(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(config.Path(dir))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	return string(b)
}

// Provisioning is necessary and not sufficient: without this key every exec
// child still runs at the owner's UID, so a fully provisioned machine could
// have the protection built and switched off.
func TestEnablePrivsep_CreatesTheConfigWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	changed, err := enablePrivsepInConfig(dir, 0, 0)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !changed {
		t.Fatal("reported no change while creating the setting")
	}
	got := readCfg(t, dir)
	if !strings.Contains(got, "[security]") || !strings.Contains(got, "privsep = true") {
		t.Errorf("config does not enable privsep:\n%s", got)
	}
	if cfg, perr := config.Parse([]byte(got)); perr != nil {
		t.Errorf("wrote a config byn cannot parse: %v", perr)
	} else if !cfg.PrivsepEnabled() {
		t.Error("byn parses the written config as privsep off")
	}
}

// The file is hand-written and hand-read, so everything else in it — including
// the comments that explain it — has to survive.
func TestEnablePrivsep_KeepsTheRestOfTheFile(t *testing.T) {
	dir := t.TempDir()
	original := "# my config\n[daemon]\nidle_timeout = \"30m\"\n\n[security]\n# how long a session lives\nsession_ttl = \"8h\"\n"
	if err := os.WriteFile(filepath.Join(dir, config.Filename), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := enablePrivsepInConfig(dir, 0, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	got := readCfg(t, dir)
	for _, keep := range []string{"# my config", "idle_timeout = \"30m\"", "# how long a session lives", "session_ttl = \"8h\""} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %q:\n%s", keep, got)
		}
	}
	cfg, err := config.Parse([]byte(got))
	if err != nil {
		t.Fatalf("wrote a config byn cannot parse: %v\n%s", err, got)
	}
	if !cfg.PrivsepEnabled() {
		t.Error("privsep not enabled after the edit")
	}
}

// An explicit choice is not setup's to overturn — least of all a deliberate
// "off", where overriding it would silently re-enable something someone turned
// off on purpose.
func TestEnablePrivsep_RespectsAnExplicitSetting(t *testing.T) {
	for _, existing := range []string{
		"[security]\nprivsep = false\n",
		"[security]\nprivsep = true\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, config.Filename), []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := enablePrivsepInConfig(dir, 0, 0)
		if err != nil {
			t.Fatalf("enable: %v", err)
		}
		if changed {
			t.Errorf("overwrote an explicit setting: %q", existing)
		}
		if got := readCfg(t, dir); got != existing {
			t.Errorf("file changed:\n%s", got)
		}
	}
}

// Re-running setup must not accumulate duplicate keys — it runs on every
// upgrade.
func TestEnablePrivsep_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	if _, err := enablePrivsepInConfig(dir, 0, 0); err != nil {
		t.Fatalf("first: %v", err)
	}
	changed, err := enablePrivsepInConfig(dir, 0, 0)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if changed {
		t.Error("second run reported a change")
	}
	if n := strings.Count(readCfg(t, dir), "privsep"); n != 1 {
		t.Errorf("privsep appears %d times, want 1", n)
	}
}
