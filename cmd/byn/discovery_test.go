package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/trust"
)

// trustByn records trust for a .byn the way the daemon would, so discovery
// (read-only) sees it as trusted.
func trustByn(t *testing.T, bynDir, path string, body []byte) {
	t.Helper()
	if _, err := trust.Grant(bynDir, trust.Canonicalize(path), trust.Hash(body)); err != nil {
		t.Fatalf("seed trust: %v", err)
	}
}

func TestDiscoverScope_NoFileReturnsEmpty(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	startDir := t.TempDir()
	homeDir := t.TempDir() // unrelated path -> walk terminates at root
	sc, src, err := discoverScope(startDir, homeDir, t.TempDir(), false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src != "" {
		t.Fatalf("src=%q, want empty", src)
	}
	if sc != (cliScope{}) {
		t.Fatalf("scope=%+v", sc)
	}
}

func TestDiscoverScope_NoDiscoveryEnv(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	sc, src, err := discoverScope(t.TempDir(), t.TempDir(), t.TempDir(), false)
	if err != nil || src != "" || sc != (cliScope{}) {
		t.Fatalf("expected zero result")
	}
}

func TestDiscoverScope_EmptyFileIsStopMarker(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	if err := os.WriteFile(filepath.Join(start, ".byn"), nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sc, src, err := discoverScope(start, t.TempDir(), t.TempDir(), false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src != "" || sc != (cliScope{}) {
		t.Fatalf("empty .byn should be a stop marker, got %+v src=%q", sc, src)
	}
}

func TestDiscoverScope_AgentModeUntrustedIsFatal(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nvault = \"acme\"\n")
	if err := os.WriteFile(filepath.Join(start, ".byn"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := discoverScope(start, t.TempDir(), bynDir, true)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("expected untrusted err, got %v", err)
	}
}

// In interactive (non-agent) mode an untrusted .byn is STILL fatal — discovery
// no longer offers a y/N auto-trust, and it must not silently record trust.
func TestDiscoverScope_UntrustedInteractive_NoAutoTrust(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nvault = \"acme\"\n")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("interactive untrusted should error, got %v", err)
	}
	// And nothing was auto-trusted.
	st, _ := trust.Status(bynDir, trust.Canonicalize(tpath), trust.Hash(body))
	if st == trust.StatusTrusted {
		t.Fatal("discovery silently granted trust — it must never auto-trust")
	}
}

// A previously-trusted .byn whose content changed is refused with a CHANGED
// error — the silent-re-trust hole is closed.
func TestDiscoverScope_ChangedBynIsFatal(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	tpath := filepath.Join(start, ".byn")
	orig := []byte("[scope]\nvault = \"acme\"\n")
	if err := os.WriteFile(tpath, orig, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	trustByn(t, bynDir, tpath, orig)
	// Now tamper with the file.
	if err := os.WriteFile(tpath, []byte("[scope]\nvault = \"evil\"\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	_, _, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("expected a CHANGED error, got %v", err)
	}
}

func TestDiscoverScope_TrustedParses(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nvault = \"acme\"\nproject = \"web\"\nenv = \"dev\"\n")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	trustByn(t, bynDir, tpath, body)
	sc, src, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src == "" {
		t.Fatal("expected src path")
	}
	if sc.Vault != "acme" || sc.Project != "web" || sc.Env != "dev" {
		t.Fatalf("scope=%+v", sc)
	}
}

func TestDiscoverScope_TrustedButBadTOML(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("not toml at all = = bad")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	trustByn(t, bynDir, tpath, body)
	_, _, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestDiscoverScope_TrustedUnknownKeyRejected(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nbogus = \"x\"\n")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	trustByn(t, bynDir, tpath, body)
	_, _, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err == nil {
		t.Fatal("expected unknown-key rejection")
	}
}

func TestMergeDiscoveryScope(t *testing.T) {
	cli := cliScope{Vault: "cli"}
	disc := cliScope{Vault: "disc", Project: "p", Env: "e"}
	out := mergeDiscoveryScope(cli, disc)
	if out.Vault != "cli" {
		t.Fatalf("CLI should win: %+v", out)
	}
	if out.Project != "p" || out.Env != "e" {
		t.Fatalf("discovery should fill missing: %+v", out)
	}
}

func TestBynTargetVault(t *testing.T) {
	if got := bynTargetVault([]byte("[scope]\nvault = \"acme\"\n")); got != "acme" {
		t.Fatalf("vault = %q, want acme", got)
	}
	if got := bynTargetVault([]byte("[scope]\nproject = \"p\"\n")); got != "" {
		t.Fatalf("missing vault should be empty, got %q", got)
	}
	if got := bynTargetVault([]byte("garbage = =")); got != "" {
		t.Fatalf("unparseable should be empty, got %q", got)
	}
}
