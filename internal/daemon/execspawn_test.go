package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// fakeSpawner records the SpawnReq it received and returns a configured exit
// code (and optional error). It substitutes for the real privsep helper so the
// daemon's spawn path can be exercised in tests without provisioning.
type fakeSpawner struct {
	mu      sync.Mutex
	got     privsep.SpawnReq
	called  bool
	retCode int
	retErr  error
}

func (f *fakeSpawner) Spawn(req privsep.SpawnReq) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = req
	f.called = true
	return f.retCode, f.retErr
}

// spawnEnvelope builds an exec.spawn request envelope.
func spawnEnvelope(t *testing.T, req ipc.ExecSpawnReq) *ipc.Envelope {
	t.Helper()
	env, err := ipc.NewRequest("spawn-1", ipc.OpExecSpawn, req)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return env
}

// ctxWithPipeFDs returns a ctx carrying three real pipe fds for stdio, plus a
// cleanup that closes them. The fds are valid so the (fake) spawner's
// dup-stdio—if it ever ran—would not fail; the fakeSpawner ignores them.
func ctxWithPipeFDs(t *testing.T) context.Context {
	t.Helper()
	mk := func() *os.File {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
		return w // a writable end is a valid fd for the seam test
	}
	in, out, errf := mk(), mk(), mk()
	return withExecSpawnFDs(context.Background(), int(in.Fd()), int(out.Fd()), int(errf.Fd()))
}

// regularFileTarget writes an executable-looking regular file and returns its
// absolute path. The basename is chosen by the caller so it can be bound to the
// authorized command.
func regularFileTarget(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := dir + "/" + name
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	return p
}

// ---- stripDangerousEnv -----------------------------------------------------

func TestStripDangerousEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/evil.so",
		"TERM=xterm",
		"LD_LIBRARY_PATH=/evil/lib",
		"LD_AUDIT=/evil/audit.so",
		"DYLD_INSERT_LIBRARIES=/evil.dylib",
		"DYLD_LIBRARY_PATH=/evil/dyld",
		"DYLD_FRAMEWORK_PATH=/evil/fw",
		"HOME=/home/me",
		"MALFORMED_NO_EQUALS",
		"API_KEY=injected", // a normal var that happens to look secret-y
	}
	got := stripDangerousEnv(in)

	gotSet := map[string]bool{}
	for _, kv := range got {
		gotSet[kv] = true
	}
	// Dangerous keys must be gone.
	for _, bad := range []string{
		"LD_PRELOAD=/evil.so", "LD_LIBRARY_PATH=/evil/lib", "LD_AUDIT=/evil/audit.so",
		"DYLD_INSERT_LIBRARIES=/evil.dylib", "DYLD_LIBRARY_PATH=/evil/dyld",
		"DYLD_FRAMEWORK_PATH=/evil/fw",
	} {
		if gotSet[bad] {
			t.Errorf("dangerous entry %q survived strip", bad)
		}
	}
	// Normal vars (and the malformed, '='-less entry) must survive.
	for _, keep := range []string{
		"PATH=/usr/bin", "TERM=xterm", "HOME=/home/me", "MALFORMED_NO_EQUALS",
		"API_KEY=injected",
	} {
		if !gotSet[keep] {
			t.Errorf("expected %q to survive strip, but it was removed", keep)
		}
	}
	// Exactly the 6 dangerous entries removed: 11 in, 5 out.
	if len(got) != 5 {
		t.Errorf("len(stripped) = %d, want 5 (6 dangerous removed from 11)", len(got))
	}
	// Input must not be mutated.
	if len(in) != 11 {
		t.Errorf("input slice mutated: len = %d, want 11", len(in))
	}
}

// TestExecSpawn_StripsDangerousEnvKeepsInjected proves the strip is wired into
// the spawn path: an LD_PRELOAD in BaseEnv is gone from the child env, while a
// benign BaseEnv var and the injected secret both survive.
func TestExecSpawn_StripsDangerousEnvKeepsInjected(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("secret-api"))

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		BaseEnv:      []string{"PATH=/usr/bin", "LD_PRELOAD=/evil.so", "DYLD_INSERT_LIBRARIES=/evil.dylib"},
		AbsTarget:    target,
	}
	if resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req)); resp.Err != nil {
		t.Fatalf("unexpected error: %+v", resp.Err)
	}
	for _, kv := range fs.got.Env {
		if strings.HasPrefix(kv, "LD_PRELOAD=") || strings.HasPrefix(kv, "DYLD_INSERT_LIBRARIES=") {
			t.Errorf("dangerous env %q reached the child", kv)
		}
	}
	envMap := map[string]string{}
	for _, kv := range fs.got.Env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			envMap[kv[:i]] = kv[i+1:]
		}
	}
	if envMap["PATH"] != "/usr/bin" {
		t.Errorf("benign PATH dropped: %q", envMap["PATH"])
	}
	if envMap["API_KEY"] != "secret-api" {
		t.Errorf("injected API_KEY dropped: %q", envMap["API_KEY"])
	}
}

// ---- not provisioned -------------------------------------------------------

func TestExecSpawn_NotProvisioned(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	// d.spawner is nil unless the host happens to be provisioned; force nil so
	// the test is deterministic regardless of the host.
	d.spawner = nil

	env := spawnEnvelope(t, ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: "", Password: pw},
		AbsTarget:    "/bin/true",
	})
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), env)
	if resp.Err == nil {
		t.Fatalf("expected error, got success")
	}
	if resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", resp.Err.Code)
	}
	if resp.Err.Recover != "byn setup" {
		t.Errorf("recover = %q, want 'byn setup'", resp.Err.Recover)
	}
}

// ---- requires stdio fds ----------------------------------------------------

func TestExecSpawn_MissingFDs(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	d.spawner = &fakeSpawner{}

	env := spawnEnvelope(t, ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: "", Password: pw},
		AbsTarget:    "/bin/true",
	})
	// No withExecSpawnFDs on the ctx → !ok.
	resp := d.handleExecSpawn(context.Background(), env)
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request for missing fds, got %+v", resp.Err)
	}
}

// ---- happy path: trusted .byn + pinned action spawns -----------------------

func TestExecSpawn_TrustedPinnedAction_Spawns(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// An injected secret in the vault.
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("secret-api"))

	// A regular-file target whose basename matches the authorized command.
	target := regularFileTarget(t, "mytool")

	// Trust a .byn pinning "mytool run" so the command runs free (no password).
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{retCode: 42}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{
			Path:    byn,
			Command: "mytool run",
			Argv:    []string{"mytool", "run"},
		},
		BaseEnv:   []string{"PATH=/usr/bin", "TERM=xterm"},
		AbsTarget: target,
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err != nil {
		t.Fatalf("unexpected error: %+v", resp.Err)
	}

	var sr ipc.ExecSpawnResp
	if err := ipc.DecodeBody(ipc.BodyResp, resp, &sr); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if sr.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42 (propagated)", sr.ExitCode)
	}

	if !fs.called {
		t.Fatal("spawner was not called")
	}
	// spawnArgv[0] must be the validated absolute target.
	if len(fs.got.Argv) == 0 || fs.got.Argv[0] != target {
		t.Fatalf("Argv[0] = %v, want %q", fs.got.Argv, target)
	}
	// The remaining args come from resolvedArgv[1:].
	if len(fs.got.Argv) != 2 || fs.got.Argv[1] != "run" {
		t.Errorf("Argv = %v, want [%q run]", fs.got.Argv, target)
	}
	// childEnv must contain BOTH a BaseEnv var AND the injected secret, with the
	// injected secret appended last.
	envMap := map[string]string{}
	for _, kv := range fs.got.Env {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				envMap[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	if envMap["PATH"] != "/usr/bin" {
		t.Errorf("childEnv PATH = %q, want /usr/bin (from BaseEnv)", envMap["PATH"])
	}
	if envMap["API_KEY"] != "secret-api" {
		t.Errorf("childEnv API_KEY = %q, want secret-api (injected)", envMap["API_KEY"])
	}
}

// ---- injected value wins on duplicate key ----------------------------------

func TestExecSpawn_InjectedValueWinsOnDuplicateKey(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("from-vault"))

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		BaseEnv:      []string{"API_KEY=from-base-env"}, // collides; injected must win
		AbsTarget:    target,
	}
	if resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req)); resp.Err != nil {
		t.Fatalf("unexpected error: %+v", resp.Err)
	}
	// The LAST occurrence of API_KEY in the env slice must be the injected one.
	var last string
	for _, kv := range fs.got.Env {
		if len(kv) >= len("API_KEY=") && kv[:len("API_KEY=")] == "API_KEY=" {
			last = kv[len("API_KEY="):]
		}
	}
	if last != "from-vault" {
		t.Errorf("effective API_KEY = %q, want from-vault (injected wins, appended last)", last)
	}
}

// ---- AbsTarget validation --------------------------------------------------

func TestExecSpawn_AbsTargetMismatch(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Target basename "malware" != authorized command "mytool".
	target := regularFileTarget(t, "malware")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request for basename mismatch, got %+v", resp.Err)
	}
	if fs.called {
		t.Error("spawner must NOT be called on a target mismatch")
	}
}

func TestExecSpawn_AbsTargetNotAbsolute(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    "mytool", // relative, not absolute
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request for relative target, got %+v", resp.Err)
	}
	if fs.called {
		t.Error("spawner must NOT be called for a relative target")
	}
}

func TestExecSpawn_AbsTargetNotRegularFile(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	fs := &fakeSpawner{}
	d.spawner = fs

	// A directory named "mytool" — absolute, but not a regular file.
	dir := t.TempDir() + "/mytool"
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    dir,
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request for non-regular target, got %+v", resp.Err)
	}
	if fs.called {
		t.Error("spawner must NOT be called for a non-regular target")
	}
}

// ---- locked vault denied (not spawned, audited) ----------------------------

func TestExecSpawn_LockedVault_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	lockVaultStore(t, d, "default")

	fs := &fakeSpawner{}
	d.spawner = fs

	const cmd = "mytool run"
	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: cmd, Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err == nil || resp.Err.Code != ipc.CodeLocked {
		t.Fatalf("want locked, got %+v", resp.Err)
	}
	if fs.called {
		t.Error("spawner must NOT be called when the vault is locked")
	}

	// Authorization denial must be audited (by authorizeExec).
	ev := findExecAudit(t, c, cmd)
	if ev == nil {
		t.Fatal("no exec audit event for locked-vault spawn denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.ErrorCode != string(ipc.CodeLocked) {
		t.Errorf("error_code = %q, want %q", ev.ErrorCode, string(ipc.CodeLocked))
	}
	if ev.BynPath != trust.Canonicalize(byn) {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, trust.Canonicalize(byn))
	}
}

// ---- spawn-level failure propagated + audited ------------------------------

func TestExecSpawn_SpawnUnsupported_FallbackError(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	// Spawner returns ErrUnsupported AFTER a clean authorization.
	fs := &fakeSpawner{retCode: -1, retErr: privsep.ErrUnsupported}
	d.spawner = fs

	req := ipc.ExecSpawnReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}
	resp := d.handleExecSpawn(ctxWithPipeFDs(t), spawnEnvelope(t, req))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request fallback for ErrUnsupported, got %+v", resp.Err)
	}
	if resp.Err.Recover != "byn setup" {
		t.Errorf("recover = %q, want 'byn setup'", resp.Err.Recover)
	}
}
