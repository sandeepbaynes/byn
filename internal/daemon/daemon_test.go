package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// shortTempDir returns a short tempdir under /tmp. Required on macOS,
// where Unix socket paths are capped at 104 chars and t.TempDir()
// returns paths around 100+ chars under /var/folders/...
func shortTempDir(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dir := filepath.Join("/tmp", "byn-test-"+hex.EncodeToString(b[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// startTestDaemon brings up a daemon in a tempdir and returns the
// daemon and an ipc.Client wired to its socket. The daemon is
// shut down via t.Cleanup.
func startTestDaemon(t *testing.T) (*Daemon, *ipc.Client) {
	t.Helper()
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		d.Shutdown(2 * time.Second)
	})
	return d, ipc.NewClient(d.SocketPath())
}

func TestStart_CreatesSocketWithMode0600(t *testing.T) {
	d, _ := startTestDaemon(t)
	info, err := os.Stat(d.SocketPath())
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("socket mode = %o, want 0600", mode)
	}
}

func TestStart_WritesPidFile(t *testing.T) {
	d, _ := startTestDaemon(t)
	data, err := os.ReadFile(d.pidPath)
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		t.Fatalf("parse pidfile: %v", err)
	}
	if pid != os.Getpid() {
		t.Fatalf("pidfile pid = %d, want %d", pid, os.Getpid())
	}
}

func TestStart_RefusesDoubleStart(t *testing.T) {
	dir := shortTempDir(t)
	d1, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New d1: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d1.Start(ctx); err != nil {
		t.Fatalf("Start d1: %v", err)
	}
	defer d1.Shutdown(time.Second)

	d2, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New d2: %v", err)
	}
	err = d2.Start(ctx)
	if err == nil {
		t.Fatal("Start d2: want error, got nil")
	}
}

func TestStart_ReplacesStalePidFile(t *testing.T) {
	dir := shortTempDir(t)
	// Write a pidfile referencing a PID that almost certainly doesn't
	// exist (very high number).
	stalePID := 0x7fffffff
	if err := os.WriteFile(filepath.Join(dir, PIDFilename),
		[]byte(fmt.Sprintf("%d\n", stalePID)), 0o600); err != nil {
		t.Fatalf("seed pidfile: %v", err)
	}
	d, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start (expected to replace stale pidfile): %v", err)
	}
	defer d.Shutdown(time.Second)
}

func TestStart_CleansStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	// Create a stale (regular file standing in for) socket. We can't
	// trivially leave a real bound socket without a process; this
	// just exercises the "remove path if exists and not in use" code
	// path.
	if err := os.WriteFile(filepath.Join(dir, SocketFilename), []byte{}, 0o600); err != nil {
		t.Fatalf("seed socket: %v", err)
	}
	d, err := New(Config{Dir: dir, Version: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start with stale socket: %v", err)
	}
	defer d.Shutdown(time.Second)
}

func TestStatus_OnFreshDaemon(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.StatusResp
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &resp); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(resp.Vaults) != 0 {
		t.Fatalf("fresh daemon reports vaults = %v, want empty", resp.Vaults)
	}
	if resp.Version != "test" {
		t.Fatalf("Version = %q, want \"test\"", resp.Version)
	}
	if resp.ProtocolMin != ipc.ProtocolMin || resp.ProtocolMax != ipc.ProtocolVersion {
		t.Fatalf("ProtocolMin/Max = %d/%d, want %d/%d",
			resp.ProtocolMin, resp.ProtocolMax, ipc.ProtocolMin, ipc.ProtocolVersion)
	}
	// FDAGranted must be nil when privsep is off — the daemon runs as the
	// owner who inherits the Terminal's TCC grant; no FDA check needed.
	if resp.FDAGranted != nil {
		t.Fatalf("FDAGranted = %v, want nil (privsep off)", *resp.FDAGranted)
	}
}

// findVault returns the named vault summary from a StatusResp, or
// the zero value + false.
func findVault(resp ipc.StatusResp, name string) (ipc.VaultSummary, bool) {
	for _, v := range resp.Vaults {
		if v.Name == name {
			return v, true
		}
	}
	return ipc.VaultSummary{}, false
}

func TestInit_UnlockedAfterInit(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	var st ipc.StatusResp
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &st); err != nil {
		t.Fatalf("Status: %v", err)
	}
	v, ok := findVault(st, "default")
	if !ok {
		t.Fatalf("post-Init Status has no default vault: %v", st.Vaults)
	}
	// vault.Init returns a locked Store; caller must Unlock before
	// data-plane ops succeed.
	if !v.Locked {
		t.Fatal("post-Init default vault unlocked; init should leave it locked")
	}
}

func TestInit_RefusedSecondTime(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) {
		t.Fatalf("second Init: err = %v, want ipc.ErrResponse", err)
	}
	if ipcErr.Code != ipc.CodeAlreadyInit {
		t.Fatalf("second Init code = %s, want %s", ipcErr.Code, ipc.CodeAlreadyInit)
	}
}

func TestUnlock_WrongPassword(t *testing.T) {
	_, c := startTestDaemon(t)
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: []byte("right")}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: []byte("wrong")}, &ipc.VaultUnlockResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeWrongPassword {
		t.Fatalf("wrong password: err = %v, want WrongPassword", err)
	}
}

func TestUnlock_NoVaultLooksLikeWrongPassword(t *testing.T) {
	// No Init called — daemon has no vault. Unlock should NOT
	// distinguish this from a wrong password.
	_, c := startTestDaemon(t)
	err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: []byte("anything")}, &ipc.VaultUnlockResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) {
		t.Fatalf("err = %v, want ipc.ErrResponse", err)
	}
	if ipcErr.Code != ipc.CodeWrongPassword {
		t.Fatalf("no-vault unlock code = %s, want %s (existence oracle)", ipcErr.Code, ipc.CodeWrongPassword)
	}
}

func TestPutGetRoundtrip(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	var unlockResp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &unlockResp, nil)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	c.Session = tok
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "k", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "k"}, &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("v")) {
		t.Fatalf("Get value = %q, want \"v\"", got.Value)
	}
}

func TestPut_WhileLocked(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Don't unlock. Under NU-3, the auth gate fires before the vault lock
	// check, so a caller with no session and no password gets auth_required
	// (the daemon does not reveal vault lock state to unauthenticated callers).
	err := c.Call(ipc.OpPut, ipc.PutReq{Name: "k", Value: []byte("v")}, &ipc.PutResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeAuthRequired {
		t.Fatalf("locked Put: err = %v, want CodeAuthRequired", err)
	}
}

func TestLock_AfterUnlock(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	var unlockResp2 ipc.VaultUnlockResp
	tok2, err2 := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &unlockResp2, nil)
	if err2 != nil {
		t.Fatalf("Unlock: %v", err2)
	}
	c.Session = tok2
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	c.Session = nil
	// Under NU-3, auth gate fires before lock check: no session + no password
	// → auth_required (daemon does not reveal vault lock state to unauthenticated callers).
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "missing"}, &ipc.GetResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeAuthRequired {
		t.Fatalf("Get after Lock: err = %v, want CodeAuthRequired", err)
	}
}

func TestList_AndDelete(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	_ = c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{})
	var ulResp ipc.VaultUnlockResp
	tok, _ := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ulResp, nil)
	c.Session = tok

	for _, n := range []string{"a", "b", "c"} {
		if err := c.Call(ipc.OpPut, ipc.PutReq{Name: n, Value: []byte(n)}, &ipc.PutResp{}); err != nil {
			t.Fatalf("Put %s: %v", n, err)
		}
	}
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(lr.Secrets) != 3 {
		t.Fatalf("List len = %d, want 3", len(lr.Secrets))
	}

	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "b"}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("List 2: %v", err)
	}
	if len(lr.Secrets) != 2 {
		t.Fatalf("List len after delete = %d, want 2", len(lr.Secrets))
	}
}

func TestUnknownOp(t *testing.T) {
	_, c := startTestDaemon(t)
	err := c.Call("bogus", struct{}{}, &struct{}{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeUnknownOp {
		t.Fatalf("unknown op: err = %v, want CodeUnknownOp", err)
	}
}

func TestDaemonDown_ClientReturnsErrDaemonDown(t *testing.T) {
	c := ipc.NewClient("/tmp/byn-test-not-a-real-socket-zzzzz")
	err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &ipc.StatusResp{})
	if !errors.Is(err, ipc.ErrDaemonDown) {
		t.Fatalf("daemon down: err = %v, want ErrDaemonDown", err)
	}
}

func TestShutdown_DrainsInFlight(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte("p")
	_ = c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{})
	_ = c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = c.Call(ipc.OpPut, ipc.PutReq{Name: fmt.Sprintf("k%d", i), Value: []byte("v")}, &ipc.PutResp{})
		}(i)
	}
	wg.Wait()
	d.Shutdown(2 * time.Second)
	// Socket should be gone after shutdown.
	if _, err := os.Stat(d.SocketPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-shutdown socket stat err = %v, want ErrNotExist", err)
	}
}

// ---- v2 IPC: multi-vault, project/env CRUD, status shape ---------------

func TestVaultInit_NamedVault(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("acme-pw")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("VaultInit acme: %v", err)
	}
	var st ipc.StatusResp
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &st); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if _, ok := findVault(st, "acme"); !ok {
		t.Fatalf("status.Vaults missing 'acme': %v", st.Vaults)
	}
}

func TestVaultUnlock_NamedVault_DataIsolated(t *testing.T) {
	_, c := startTestDaemon(t)

	// Two vaults, two passwords — capture sessions for each.
	if err := c.Call(ipc.OpVaultInit,
		ipc.VaultInitReq{Name: "acme", Password: []byte("pw-acme")}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init acme: %v", err)
	}
	var acmeUnlockResp ipc.VaultUnlockResp
	acmeTok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: "acme", Password: []byte("pw-acme")}, &acmeUnlockResp, nil)
	if err != nil {
		t.Fatalf("Unlock acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultInit,
		ipc.VaultInitReq{Name: "personal", Password: []byte("pw-personal")}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("Init personal: %v", err)
	}
	var personalUnlockResp ipc.VaultUnlockResp
	personalTok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: "personal", Password: []byte("pw-personal")}, &personalUnlockResp, nil)
	if err != nil {
		t.Fatalf("Unlock personal: %v", err)
	}

	// Put a distinct value in each vault, scoping via Scope.Vault.
	c.Session = acmeTok
	if err := c.Call(ipc.OpPut,
		ipc.PutReq{Scope: ipc.Scope{Vault: "acme"}, Name: "MARKER", Value: []byte("from-acme")},
		&ipc.PutResp{}); err != nil {
		t.Fatalf("Put acme: %v", err)
	}
	c.Session = personalTok
	if err := c.Call(ipc.OpPut,
		ipc.PutReq{Scope: ipc.Scope{Vault: "personal"}, Name: "MARKER", Value: []byte("from-personal")},
		&ipc.PutResp{}); err != nil {
		t.Fatalf("Put personal: %v", err)
	}

	// Each vault sees only its own value.
	var got ipc.GetResp
	c.Session = acmeTok
	if err := c.Call(ipc.OpGet,
		ipc.GetReq{Scope: ipc.Scope{Vault: "acme"}, Name: "MARKER"}, &got); err != nil {
		t.Fatalf("Get acme: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("from-acme")) {
		t.Fatalf("acme MARKER = %q, want from-acme", got.Value)
	}
	c.Session = personalTok
	if err := c.Call(ipc.OpGet,
		ipc.GetReq{Scope: ipc.Scope{Vault: "personal"}, Name: "MARKER"}, &got); err != nil {
		t.Fatalf("Get personal: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("from-personal")) {
		t.Fatalf("personal MARKER = %q, want from-personal", got.Value)
	}
}

func TestVaultLock_All(t *testing.T) {
	_, c := startTestDaemon(t)
	for _, v := range []string{"default", "acme"} {
		_ = c.Call(ipc.OpVaultInit,
			ipc.VaultInitReq{Name: v, Password: []byte("pw")}, &ipc.VaultInitResp{})
		_ = c.Call(ipc.OpVaultUnlock,
			ipc.VaultUnlockReq{Name: v, Password: []byte("pw")}, &ipc.VaultUnlockResp{})
	}
	var resp ipc.VaultLockResp
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{Name: "*"}, &resp); err != nil {
		t.Fatalf("VaultLock *: %v", err)
	}
	if resp.Locked != 2 {
		t.Fatalf("Locked count = %d, want 2", resp.Locked)
	}
}

func TestProjectCRUD_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpProjectCreate,
		ipc.ProjectCreateReq{Name: "billing"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("ProjectCreate: %v", err)
	}
	var pl ipc.ProjectListResp
	if err := c.Call(ipc.OpProjectList, ipc.ProjectListReq{}, &pl); err != nil {
		t.Fatalf("ProjectList: %v", err)
	}
	names := make(map[string]bool)
	for _, p := range pl.Projects {
		names[p.Name] = true
	}
	if !names["billing"] || !names["default"] {
		t.Fatalf("projects = %v, want billing + default", pl.Projects)
	}
	if err := c.Call(ipc.OpProjectRename,
		ipc.ProjectRenameReq{OldName: "billing", NewName: "billing-v2"}, &ipc.ProjectRenameResp{}); err != nil {
		t.Fatalf("ProjectRename: %v", err)
	}
	if err := c.Call(ipc.OpProjectDelete,
		ipc.ProjectDeleteReq{Name: "billing-v2"}, &ipc.ProjectDeleteResp{}); err != nil {
		t.Fatalf("ProjectDelete: %v", err)
	}
}

func TestEnvCRUD_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpEnvCreate,
		ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("EnvCreate: %v", err)
	}
	var el ipc.EnvListResp
	if err := c.Call(ipc.OpEnvList,
		ipc.EnvListReq{Project: "default"}, &el); err != nil {
		t.Fatalf("EnvList: %v", err)
	}
	if len(el.Envs) != 2 {
		t.Fatalf("envs = %v, want 2 (default + stg)", el.Envs)
	}
	// Default env must be pinned first.
	if !el.Envs[0].IsDefault {
		t.Fatalf("first env = %+v, want IsDefault=true", el.Envs[0])
	}
	// Refuses to delete default.
	err := c.Call(ipc.OpEnvDelete,
		ipc.EnvDeleteReq{Project: "default", Name: "default"}, &ipc.EnvDeleteResp{})
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) || ipcErr.Code != ipc.CodeEnvProtected {
		t.Fatalf("EnvDelete default: err = %v, want CodeEnvProtected", err)
	}
}

func TestPut_InheritanceVisible(t *testing.T) {
	// Put in default env, Get from non-default env returns Source="default".
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	_ = c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "local"}, &ipc.EnvCreateResp{})

	// Put in default env.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{Env: "default"}, Name: "BASE", Value: []byte("v"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put default: %v", err)
	}

	// Get from local env — should inherit, with Source="default".
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{
		Scope: ipc.Scope{Env: "local"}, Name: "BASE",
	}, &got); err != nil {
		t.Fatalf("Get local: %v", err)
	}
	if got.Source != "default" {
		t.Fatalf("Source = %q, want \"default\"", got.Source)
	}

	// Override in local.
	if err := c.Call(ipc.OpPut, ipc.PutReq{
		Scope: ipc.Scope{Env: "local"}, Name: "BASE", Value: []byte("override"),
	}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put local: %v", err)
	}
	if err := c.Call(ipc.OpGet, ipc.GetReq{
		Scope: ipc.Scope{Env: "local"}, Name: "BASE",
	}, &got); err != nil {
		t.Fatalf("Get local override: %v", err)
	}
	if got.Source != "scope" || !bytes.Equal(got.Value, []byte("override")) {
		t.Fatalf("override: Source=%q Value=%q want scope/override", got.Source, got.Value)
	}
}

func TestStatus_ExposesProtocolMinMax(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.StatusResp
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &resp); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.ProtocolMax != ipc.ProtocolVersion {
		t.Fatalf("ProtocolMax = %d, want %d", resp.ProtocolMax, ipc.ProtocolVersion)
	}
	if resp.ProtocolMin != ipc.ProtocolMin {
		t.Fatalf("ProtocolMin = %d, want %d", resp.ProtocolMin, ipc.ProtocolMin)
	}
}

func TestConcurrentClients(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("k%02d", i)
			if err := c.Call(ipc.OpPut, ipc.PutReq{Name: name, Value: []byte("v")}, &ipc.PutResp{}); err != nil {
				t.Errorf("Put %s: %v", name, err)
			}
			var got ipc.GetResp
			if err := c.Call(ipc.OpGet, ipc.GetReq{Name: name}, &got); err != nil {
				t.Errorf("Get %s: %v", name, err)
			}
		}(i)
	}
	wg.Wait()
}
