package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sandeepbaynes/byn/internal/trust"
)

// trustByn records trust for a .byn the way the daemon would, so discovery
// (read-only) sees it as trusted. Uses trust.Put directly (Grant was removed;
// Status-based discovery only needs the path+hash, not MACs).
func trustByn(t *testing.T, bynDir, path string, body []byte) {
	t.Helper()
	rec := trust.Record{Path: trust.Canonicalize(path), SHA256: trust.Hash(body)}
	if _, err := trust.Put(bynDir, rec); err != nil {
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
	if !reflect.DeepEqual(sc, cliScope{}) {
		t.Fatalf("scope=%+v", sc)
	}
}

func TestDiscoverScope_NoDiscoveryEnv(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "1")
	sc, src, err := discoverScope(t.TempDir(), t.TempDir(), t.TempDir(), false)
	if err != nil || src != "" || !reflect.DeepEqual(sc, cliScope{}) {
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
	if src != "" || !reflect.DeepEqual(sc, cliScope{}) {
		t.Fatalf("empty .byn should be a stop marker, got %+v src=%q", sc, src)
	}
}

// Discovery resolves the scope from any .byn — trust is NOT checked here (only
// `byn exec` gates on trust). An untrusted .byn yields its scope, not an error,
// in both agent and interactive mode, and discovery never auto-trusts.
func TestDiscoverScope_ResolvesUntrusted(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nvault = \"acme\"\n")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, agent := range []bool{true, false} {
		sc, src, err := discoverScope(start, t.TempDir(), bynDir, agent)
		if err != nil {
			t.Fatalf("agent=%v: untrusted .byn should resolve, got %v", agent, err)
		}
		if src != tpath || sc.Vault != "acme" {
			t.Fatalf("agent=%v: scope=%+v src=%q", agent, sc, src)
		}
	}
	if st, _ := trust.Status(bynDir, trust.Canonicalize(tpath), trust.Hash(body)); st == trust.StatusTrusted {
		t.Fatal("discovery must never auto-trust")
	}
}

// A changed .byn also just resolves — the trust/CHANGED check now lives in
// `byn exec`, not discovery.
func TestDiscoverScope_ResolvesChanged(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	tpath := filepath.Join(start, ".byn")
	orig := []byte("[scope]\nvault = \"acme\"\n")
	if err := os.WriteFile(tpath, orig, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	trustByn(t, bynDir, tpath, orig)
	if err := os.WriteFile(tpath, []byte("[scope]\nvault = \"evil\"\n"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	sc, _, err := discoverScope(start, t.TempDir(), bynDir, false)
	if err != nil {
		t.Fatalf("changed .byn should resolve in discovery, got %v", err)
	}
	if sc.Vault != "evil" {
		t.Fatalf("scope=%+v", sc)
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
	// Explicit vault name.
	if got, err := bynTargetVault([]byte("[scope]\nvault = \"acme\"\n")); err != nil || got != "acme" {
		t.Fatalf("vault = (%q, %v), want (acme, nil)", got, err)
	}
	// No vault specified → empty string + NIL error (resolves to default).
	if got, err := bynTargetVault([]byte("[scope]\nproject = \"p\"\n")); err != nil || got != "" {
		t.Fatalf("missing vault = (%q, %v), want (\"\", nil)", got, err)
	}
	// Parse error → empty string + NON-NIL error (must NOT masquerade as the
	// default vault — this is the latent trap the fix closes).
	if got, err := bynTargetVault([]byte("garbage = =")); err == nil || got != "" {
		t.Fatalf("unparseable = (%q, %v), want (\"\", err)", got, err)
	}
}
