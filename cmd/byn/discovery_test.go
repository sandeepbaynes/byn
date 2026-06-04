package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashBynFile_Deterministic(t *testing.T) {
	a := hashBynFile([]byte("hello"))
	b := hashBynFile([]byte("hello"))
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	c := hashBynFile([]byte("world"))
	if a == c {
		t.Fatal("collisions are not okay")
	}
	if len(a) != 64 {
		t.Fatalf("hex length = %d, want 64", len(a))
	}
}

func TestCanonicalize_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := canonicalize(p)
	if got == "" {
		t.Fatal("empty")
	}
	// Should produce an absolute path.
	if !filepath.IsAbs(got) {
		t.Fatalf("not absolute: %q", got)
	}
}

func TestCanonicalize_MissingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nope")
	got := canonicalize(p)
	if !filepath.IsAbs(got) {
		t.Fatalf("missing should still abs, got %q", got)
	}
}

func TestTrustStore_EmptyOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	ts, err := loadTrustStore(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ts == nil || len(ts.Records) != 0 {
		t.Fatalf("expected empty store, got %v", ts)
	}
}

func TestTrustStore_AddAndCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), ".byn")
	body := []byte("[scope]\nvault = \"a\"\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := addTrust(dir, path, body); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
	ok, err := isTrusted(dir, path, body)
	if err != nil {
		t.Fatalf("isTrusted: %v", err)
	}
	if !ok {
		t.Fatal("expected trusted")
	}
	// Mismatched content fails.
	ok, _ = isTrusted(dir, path, []byte("[scope]\nvault = \"b\"\n"))
	if ok {
		t.Fatal("different content should not match")
	}
	// File mode 0600.
	info, _ := os.Stat(filepath.Join(dir, trustFile))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestAddTrust_UpdatesExistingRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), ".byn")
	body1 := []byte("v1")
	if err := os.WriteFile(path, body1, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := addTrust(dir, path, body1); err != nil {
		t.Fatalf("addTrust1: %v", err)
	}
	body2 := []byte("v2")
	if err := addTrust(dir, path, body2); err != nil {
		t.Fatalf("addTrust2: %v", err)
	}
	// Only one record, with v2's hash.
	ts, _ := loadTrustStore(dir)
	if len(ts.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(ts.Records))
	}
	if ts.Records[0].SHA256 != hashBynFile(body2) {
		t.Fatal("record not updated to new hash")
	}
}

func TestRemoveTrust(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), ".byn")
	body := []byte("x")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := addTrust(dir, path, body); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
	removed, err := removeTrust(dir, path)
	if err != nil {
		t.Fatalf("removeTrust: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true")
	}
	removed2, err := removeTrust(dir, path)
	if err != nil {
		t.Fatalf("removeTrust idempotent: %v", err)
	}
	if removed2 {
		t.Fatal("expected removed=false on second call")
	}
}

func TestLoadTrustStore_BadJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, trustFile), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadTrustStore(dir)
	if err == nil {
		t.Fatal("expected JSON parse error")
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

func TestDiscoverScope_TrustedParses(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	start := t.TempDir()
	bynDir := t.TempDir()
	body := []byte("[scope]\nvault = \"acme\"\nproject = \"web\"\nenv = \"dev\"\n")
	tpath := filepath.Join(start, ".byn")
	if err := os.WriteFile(tpath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := addTrust(bynDir, tpath, body); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
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
	if err := addTrust(bynDir, tpath, body); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
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
	if err := addTrust(bynDir, tpath, body); err != nil {
		t.Fatalf("addTrust: %v", err)
	}
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
