package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonConfigFor_DefaultIdleTimeout(t *testing.T) {
	dir := t.TempDir()
	cfg, err := daemonConfigFor(dir)
	if err != nil {
		t.Fatalf("daemonConfigFor: %v", err)
	}
	if cfg.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want 15m (default when no config file)", cfg.IdleTimeout)
	}
	if cfg.Dir != dir {
		t.Errorf("Dir = %q, want %q", cfg.Dir, dir)
	}
}

func TestDaemonConfigFor_ReadsIdleTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"),
		[]byte("[daemon]\nidle_timeout = \"3m\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := daemonConfigFor(dir)
	if err != nil {
		t.Fatalf("daemonConfigFor: %v", err)
	}
	if cfg.IdleTimeout != 3*time.Minute {
		t.Errorf("IdleTimeout = %v, want 3m", cfg.IdleTimeout)
	}
}

func TestDaemonConfigFor_BadConfig_Errors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"),
		[]byte("[daemon]\nidle_timeout = \"nope\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := daemonConfigFor(dir); err == nil {
		t.Fatal("daemonConfigFor(bad config) error = nil, want error")
	}
}
