package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testPassword = "opensesame-correct-horse"

// newOpenedVault returns a freshly-init'd, unlocked Store and its
// root dir. Vault has the bootstrapped default project + default env.
func newOpenedVault(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	password := []byte(testPassword)
	st, err := Init(context.Background(), dir, DefaultVaultName, password)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Unlock(password); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	return st, dir
}

// defaultScope is the Scope used by tests that don't care about
// non-default envs.
func defaultScope() Scope {
	return Scope{Project: DefaultProjectName, Env: DefaultEnvName}
}

// ---- init / open --------------------------------------------------------

func TestInit_CreatesFiles(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = st.Close() }()

	vdir := Dir(dir, DefaultVaultName)
	for _, f := range []string{dbFilename, wrappedFilename, MetaFilename} {
		p := filepath.Join(vdir, f)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", f, mode)
		}
	}
}

func TestInit_BootstrapsDefaultProjectAndEnv(t *testing.T) {
	st, _ := newOpenedVault(t)
	projects, err := st.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 1 || projects[0].Name != DefaultProjectName {
		t.Fatalf("projects = %v, want [%s]", projects, DefaultProjectName)
	}
	envs, err := st.ListEnvs(context.Background(), DefaultProjectName)
	if err != nil {
		t.Fatalf("ListEnvs: %v", err)
	}
	if len(envs) != 1 || envs[0].Name != DefaultEnvName || !envs[0].IsDefault {
		t.Fatalf("envs = %v, want exactly default env", envs)
	}
}

func TestInit_RefusesSecondTime(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_ = st.Close()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw")); !errors.Is(err, ErrAlreadyInit) {
		t.Fatalf("second Init: err = %v, want ErrAlreadyInit", err)
	}
}

func TestOpen_NoVault(t *testing.T) {
	if _, err := Open(context.Background(), t.TempDir(), DefaultVaultName); !errors.Is(err, ErrNotInit) {
		t.Fatalf("Open empty dir: err = %v, want ErrNotInit", err)
	}
}

func TestOpen_PartialState(t *testing.T) {
	dir := t.TempDir()
	vdir := Dir(dir, DefaultVaultName)
	if err := os.MkdirAll(vdir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vdir, dbFilename), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Open(context.Background(), dir, DefaultVaultName)
	if err == nil || !strings.Contains(err.Error(), "partial state") {
		t.Fatalf("partial state Open: err = %v, want partial-state error", err)
	}
}

func TestOpen_AfterInit_DataSurvives(t *testing.T) {
	dir := t.TempDir()
	pw := []byte("pw1234")
	st1, err := Init(context.Background(), dir, DefaultVaultName, pw)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := st1.Unlock(pw); err != nil {
		t.Fatalf("Unlock1: %v", err)
	}
	if err := st1.PutEnvVar(context.Background(), defaultScope(), "k1", []byte("v1"), PutOpt{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_ = st1.Close()

	st2, err := Open(context.Background(), dir, DefaultVaultName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st2.Close() }()
	if err := st2.Unlock(pw); err != nil {
		t.Fatalf("Unlock2: %v", err)
	}
	got, err := st2.GetEnvVar(context.Background(), defaultScope(), "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("v1")) {
		t.Fatalf("Get value = %q, want %q", got.Value, "v1")
	}
	if got.Source != SourceScope {
		t.Fatalf("Source = %v, want SourceScope", got.Source)
	}
}

func TestUnlock_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte("right")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	st, err := Open(context.Background(), dir, DefaultVaultName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Unlock([]byte("wrong")); err == nil {
		t.Fatal("Unlock with wrong password succeeded")
	}
	if !st.IsLocked() {
		t.Fatal("vault not locked after failed unlock")
	}
}

// ---- locked behavior ---------------------------------------------------

func TestLockedOps(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	st, err := Open(context.Background(), dir, DefaultVaultName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if !st.IsLocked() {
		t.Fatal("freshly Open()ed vault should be locked")
	}
	if err := st.PutEnvVar(context.Background(), defaultScope(), "x", []byte("v"), PutOpt{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("Put while locked: err = %v, want ErrLocked", err)
	}
	if _, err := st.GetEnvVar(context.Background(), defaultScope(), "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get while locked: err = %v, want ErrLocked", err)
	}
	// List doesn't require unlock — metadata-only.
	if _, err := st.ListEnvVars(context.Background(), defaultScope()); err != nil {
		t.Fatalf("List while locked: %v", err)
	}
	// Delete doesn't require unlock either.
	if err := st.DeleteEnvVar(context.Background(), defaultScope(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete missing while locked: err = %v, want ErrNotFound", err)
	}
	// Rename DOES require unlock because it re-encrypts under new AAD.
	if err := st.RenameEnvVar(context.Background(), defaultScope(), "a", "b"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Rename while locked: err = %v, want ErrLocked", err)
	}
}

func TestLock_ZerosKey(t *testing.T) {
	st, _ := newOpenedVault(t)
	if st.IsLocked() {
		t.Fatal("newly Unlock()ed vault is locked")
	}
	st.mu.RLock()
	keyRef := st.vaultKey
	st.mu.RUnlock()
	keyCopy := append([]byte(nil), keyRef...)

	st.Lock()
	if !st.IsLocked() {
		t.Fatal("vault not locked after Lock()")
	}
	if bytes.Equal(keyRef, keyCopy) {
		t.Fatal("Lock did not zero key bytes")
	}
	for _, b := range keyRef {
		if b != 0 {
			t.Fatalf("Lock left non-zero byte in vault key: %v", keyRef)
		}
	}
}

// ---- env_var CRUD in default scope -------------------------------------

func TestPutEnvVar_GetEnvVar_Roundtrip(t *testing.T) {
	st, _ := newOpenedVault(t)
	cases := map[string][]byte{
		"empty":      {},
		"simple":     []byte("hello"),
		"binary":     {0, 1, 2, 0xff},
		"large":      bytes.Repeat([]byte{0xab}, 1024),
		"unicode":    []byte("π × 🔑"),
		"AWS_ACCESS": []byte("AKIA..."),
		"with_under": []byte("ok"),
	}
	ctx := context.Background()
	for name, val := range cases {
		if err := st.PutEnvVar(ctx, defaultScope(), name, val, PutOpt{}); err != nil {
			t.Fatalf("Put %q: %v", name, err)
		}
		got, err := st.GetEnvVar(ctx, defaultScope(), name)
		if err != nil {
			t.Fatalf("Get %q: %v", name, err)
		}
		if !bytes.Equal(got.Value, val) {
			t.Fatalf("Get %q value = %q, want %q", name, got.Value, val)
		}
	}
}

func TestPutEnvVar_UpsertPreservesCreatedAt(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v1"), PutOpt{}); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	first, err := st.GetEnvVar(ctx, defaultScope(), "k")
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v2"), PutOpt{}); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	second, err := st.GetEnvVar(ctx, defaultScope(), "k")
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("upsert changed CreatedAt: %v → %v", first.CreatedAt, second.CreatedAt)
	}
}

func TestPutEnvVar_CreateOnlyConflict(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v"), PutOpt{CreateOnly: true}); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v2"), PutOpt{CreateOnly: true})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("Put CreateOnly on existing: err = %v, want ErrExists", err)
	}
}

func TestGetEnvVar_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	_, err := st.GetEnvVar(context.Background(), defaultScope(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing: err = %v, want ErrNotFound", err)
	}
}

func TestListEnvVars_OrdersByName(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	for _, name := range []string{"c", "a", "b"} {
		if err := st.PutEnvVar(ctx, defaultScope(), name, []byte("v"), PutOpt{}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	got, err := st.ListEnvVars(ctx, defaultScope())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("List len = %d, want %d", len(got), len(want))
	}
	for i, m := range got {
		if m.Name != want[i] {
			t.Fatalf("List[%d] = %s, want %s", i, m.Name, want[i])
		}
		if m.Source != SourceScope {
			t.Fatalf("List[%d].Source = %v, want SourceScope", i, m.Source)
		}
	}
}

func TestDeleteEnvVar(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.DeleteEnvVar(ctx, defaultScope(), "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := st.GetEnvVar(ctx, defaultScope(), "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
	}
	if err := st.DeleteEnvVar(ctx, defaultScope(), "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete: err = %v, want ErrNotFound", err)
	}
}

func TestRenameEnvVar(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "a", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := st.RenameEnvVar(ctx, defaultScope(), "a", "b"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := st.GetEnvVar(ctx, defaultScope(), "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get old name: err = %v, want ErrNotFound", err)
	}
	got, err := st.GetEnvVar(ctx, defaultScope(), "b")
	if err != nil {
		t.Fatalf("Get new name: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("v")) {
		t.Fatalf("renamed value = %q, want %q", got.Value, "v")
	}
}

func TestRenameEnvVar_DestExists(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	_ = st.PutEnvVar(ctx, defaultScope(), "a", []byte("va"), PutOpt{})
	_ = st.PutEnvVar(ctx, defaultScope(), "b", []byte("vb"), PutOpt{})
	if err := st.RenameEnvVar(ctx, defaultScope(), "a", "b"); !errors.Is(err, ErrExists) {
		t.Fatalf("Rename to existing: err = %v, want ErrExists", err)
	}
}

func TestBadEntryName(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	bad := []string{"", "\x00", "hi\x00bye", strings.Repeat("a", MaxNameLen+1)}
	for _, n := range bad {
		if err := st.PutEnvVar(ctx, defaultScope(), n, []byte("v"), PutOpt{}); !errors.Is(err, ErrBadName) {
			t.Fatalf("Put %q: err = %v, want ErrBadName", n, err)
		}
	}
}

// ---- inheritance --------------------------------------------------------

func TestInheritance_DefaultFallback(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "local"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	defaultS := defaultScope()
	localS := Scope{Project: DefaultProjectName, Env: "local"}

	// Set FOO in default only.
	if err := st.PutEnvVar(ctx, defaultS, "FOO", []byte("base"), PutOpt{}); err != nil {
		t.Fatalf("Put default: %v", err)
	}
	// GetEnvVar in local should fall back.
	got, err := st.GetEnvVar(ctx, localS, "FOO")
	if err != nil {
		t.Fatalf("Get local: %v", err)
	}
	if string(got.Value) != "base" {
		t.Fatalf("inherited value = %q, want %q", got.Value, "base")
	}
	if got.Source != SourceDefault {
		t.Fatalf("Source = %v, want SourceDefault", got.Source)
	}

	// Override in local.
	if err := st.PutEnvVar(ctx, localS, "FOO", []byte("local-override"), PutOpt{}); err != nil {
		t.Fatalf("Put local: %v", err)
	}
	got, err = st.GetEnvVar(ctx, localS, "FOO")
	if err != nil {
		t.Fatalf("Get local after override: %v", err)
	}
	if string(got.Value) != "local-override" {
		t.Fatalf("override value = %q, want %q", got.Value, "local-override")
	}
	if got.Source != SourceScope {
		t.Fatalf("Source = %v, want SourceScope", got.Source)
	}
	// Default scope still shows the base value.
	got, err = st.GetEnvVar(ctx, defaultS, "FOO")
	if err != nil {
		t.Fatalf("Get default: %v", err)
	}
	if string(got.Value) != "base" {
		t.Fatalf("default value after local override = %q, want %q", got.Value, "base")
	}
}

func TestInheritance_ListMerges(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "local"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	defaultS := defaultScope()
	localS := Scope{Project: DefaultProjectName, Env: "local"}

	_ = st.PutEnvVar(ctx, defaultS, "SHARED", []byte("base"), PutOpt{})
	_ = st.PutEnvVar(ctx, defaultS, "BOTH", []byte("base"), PutOpt{})
	_ = st.PutEnvVar(ctx, localS, "BOTH", []byte("local"), PutOpt{})
	_ = st.PutEnvVar(ctx, localS, "LOCAL_ONLY", []byte("local"), PutOpt{})

	infos, err := st.ListEnvVars(ctx, localS)
	if err != nil {
		t.Fatalf("List local: %v", err)
	}
	bySource := map[string]Source{}
	for _, info := range infos {
		bySource[info.Name] = info.Source
	}
	if bySource["SHARED"] != SourceDefault {
		t.Errorf("SHARED.Source = %v, want SourceDefault", bySource["SHARED"])
	}
	if bySource["BOTH"] != SourceScope {
		t.Errorf("BOTH.Source = %v, want SourceScope (override)", bySource["BOTH"])
	}
	if bySource["LOCAL_ONLY"] != SourceScope {
		t.Errorf("LOCAL_ONLY.Source = %v, want SourceScope", bySource["LOCAL_ONLY"])
	}
	if len(infos) != 3 {
		t.Errorf("len(infos) = %d, want 3", len(infos))
	}
}

// ---- project / env management ------------------------------------------

func TestCreateProject_AndDefaults(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateProject(ctx, "billing"); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	envs, err := st.ListEnvs(ctx, "billing")
	if err != nil {
		t.Fatalf("ListEnvs: %v", err)
	}
	if len(envs) != 1 || envs[0].Name != DefaultEnvName || !envs[0].IsDefault {
		t.Fatalf("billing envs = %v, want exactly default", envs)
	}
}

func TestCreateProject_DuplicateRefused(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.CreateProject(context.Background(), "x"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := st.CreateProject(context.Background(), "x"); !errors.Is(err, ErrProjectExists) {
		t.Fatalf("second: err = %v, want ErrProjectExists", err)
	}
}

func TestCreateProject_RejectsBadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	for _, n := range []string{"", "UPPER", "_leading"} {
		if err := st.CreateProject(context.Background(), n); !errors.Is(err, ErrBadProjectName) {
			t.Errorf("CreateProject(%q) err = %v, want ErrBadProjectName", n, err)
		}
	}
}

func TestDeleteProject_LastIsAllowed(t *testing.T) {
	// A vault with zero projects is a valid state; nothing in the
	// design requires "at least one project". Deleting the last one
	// should succeed and leave ListProjects returning an empty list.
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.DeleteProject(ctx, DefaultProjectName); err != nil {
		t.Fatalf("DeleteProject last: %v", err)
	}
	projects, err := st.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("projects after deleting last = %v, want empty", projects)
	}
	// Sanity: a subsequent create-project still works.
	if err := st.CreateProject(ctx, "fresh"); err != nil {
		t.Fatalf("CreateProject after empty: %v", err)
	}
}

func TestDeleteProject_CascadesEntries(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	_ = st.CreateProject(ctx, "billing")
	_ = st.PutEnvVar(ctx, Scope{Project: "billing", Env: DefaultEnvName}, "K", []byte("v"), PutOpt{})

	if err := st.DeleteProject(ctx, "billing"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if _, err := st.ListEnvs(ctx, "billing"); !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("ListEnvs after delete: err = %v, want ErrProjectNotFound", err)
	}
}

func TestRenameProject(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	_ = st.CreateProject(ctx, "old")
	if err := st.RenameProject(ctx, "old", "new"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	projects, _ := st.ListProjects(ctx)
	found := false
	for _, p := range projects {
		if p.Name == "new" {
			found = true
		}
	}
	if !found {
		t.Fatalf("renamed project not in list: %v", projects)
	}
}

func TestCreateEnv_AndDelete(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.CreateEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("CreateEnv: %v", err)
	}
	envs, _ := st.ListEnvs(ctx, DefaultProjectName)
	if len(envs) != 2 {
		t.Fatalf("envs = %v, want 2", envs)
	}
	if err := st.DeleteEnv(ctx, DefaultProjectName, "stg"); err != nil {
		t.Fatalf("DeleteEnv: %v", err)
	}
}

func TestDeleteEnv_RefusesDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.DeleteEnv(context.Background(), DefaultProjectName, DefaultEnvName); !errors.Is(err, ErrEnvProtected) {
		t.Fatalf("DeleteEnv default: err = %v, want ErrEnvProtected", err)
	}
}

func TestRenameEnv_RefusesDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.RenameEnv(ctx, DefaultProjectName, DefaultEnvName, "x"); !errors.Is(err, ErrEnvProtected) {
		t.Fatalf("Rename default: err = %v, want ErrEnvProtected", err)
	}
	_ = st.CreateEnv(ctx, DefaultProjectName, "stg")
	if err := st.RenameEnv(ctx, DefaultProjectName, "stg", DefaultEnvName); !errors.Is(err, ErrEnvProtected) {
		t.Fatalf("Rename TO default: err = %v, want ErrEnvProtected", err)
	}
}

func TestCreateEnv_RefusesNamedDefault(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.CreateEnv(context.Background(), DefaultProjectName, DefaultEnvName); !errors.Is(err, ErrEnvExists) {
		t.Fatalf("CreateEnv default: err = %v, want ErrEnvExists", err)
	}
}

// ---- AAD binding -------------------------------------------------------

func TestEntryAAD_DiffersAcrossNames(t *testing.T) {
	st, _ := newOpenedVault(t)
	if bytes.Equal(st.entryAAD("env_var", "A"), st.entryAAD("env_var", "B")) {
		t.Fatal("AAD identical across different names — should not be")
	}
	if bytes.Equal(st.entryAAD("env_var", "X"), st.entryAAD("file", "X")) {
		t.Fatal("AAD identical across kinds — should not be")
	}
}

func TestAADTamper_SwappingCiphertextDetected(t *testing.T) {
	// Encrypting two different names with AAD-binding then swapping
	// the value blobs in DB should make decryption fail. This proves
	// that within-vault row swaps don't decrypt cleanly.
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	_ = st.PutEnvVar(ctx, defaultScope(), "A", []byte("alpha"), PutOpt{})
	_ = st.PutEnvVar(ctx, defaultScope(), "B", []byte("beta"), PutOpt{})

	// Read both ciphertexts and swap them in-place.
	projID, envID, err := st.scopeIDs(ctx, defaultScope())
	if err != nil {
		t.Fatalf("scopeIDs: %v", err)
	}
	var ctA, ctB []byte
	if err := st.db.QueryRowContext(ctx,
		`SELECT value FROM entries WHERE project_id=? AND env_id=? AND name=?`,
		projID, envID, "A").Scan(&ctA); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if err := st.db.QueryRowContext(ctx,
		`SELECT value FROM entries WHERE project_id=? AND env_id=? AND name=?`,
		projID, envID, "B").Scan(&ctB); err != nil {
		t.Fatalf("read B: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		`UPDATE entries SET value=? WHERE project_id=? AND env_id=? AND name=?`,
		ctB, projID, envID, "A"); err != nil {
		t.Fatalf("swap A: %v", err)
	}
	if _, err := st.db.ExecContext(ctx,
		`UPDATE entries SET value=? WHERE project_id=? AND env_id=? AND name=?`,
		ctA, projID, envID, "B"); err != nil {
		t.Fatalf("swap B: %v", err)
	}
	if _, err := st.GetEnvVar(ctx, defaultScope(), "A"); err == nil {
		t.Fatal("Get A after row swap succeeded; AAD should have rejected")
	}
}

// ---- schema verification -----------------------------------------------

func TestSchema_RejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	st, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := st.db.ExecContext(context.Background(),
		`UPDATE meta SET value = '999' WHERE key = 'schema_version'`); err != nil {
		t.Fatalf("smash schema_version: %v", err)
	}
	_ = st.Close()

	if _, err := Open(context.Background(), dir, DefaultVaultName); !errors.Is(err, ErrSchemaUnknown) {
		t.Fatalf("Open newer schema: err = %v, want ErrSchemaUnknown", err)
	}
}

// ---- concurrency -------------------------------------------------------

// TestConcurrent_PutDuringLock proves the vault-key race is closed.
// Pre-fix: a put racing Lock would seal ciphertext under a zero key
// because the put's "key := s.vaultKey" only copied the slice header
// and Lock's zero(s.vaultKey) wrote through the shared backing array
// mid-AEAD. After the fix, snapshotVaultKey() copies bytes into a
// fresh backing array under the read lock, so the put's local key
// is immune to Lock's zero.
//
// Run with -race to catch the data race directly; the value-check
// after re-unlock catches the silent corruption form even without -race.
func TestConcurrent_PutDuringLock(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	const iters = 50
	var wg sync.WaitGroup
	failed := false
	for i := 0; i < iters; i++ {
		name := fmt.Sprintf("race_%02d", i)
		val := []byte(fmt.Sprintf("the-quick-brown-fox-%02d", i))
		// 1. Put while occasionally locking.
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = st.PutEnvVar(ctx, defaultScope(), name, val, PutOpt{})
		}()
		go func() {
			defer wg.Done()
			st.Lock()
		}()
		wg.Wait()
		// 2. Unlock and try to read back. If the put won the race, the
		//    value must be intact; if Lock won, the put returned
		//    ErrLocked (also fine — we just skip). The fail case is
		//    a put that succeeded with corrupted ciphertext.
		if err := st.Unlock([]byte(testPassword)); err != nil {
			t.Fatalf("re-unlock #%d: %v", i, err)
		}
		got, err := st.GetEnvVar(ctx, defaultScope(), name)
		if errors.Is(err, ErrNotFound) {
			// Put lost the race to Lock; that's fine.
			continue
		}
		if err != nil {
			t.Errorf("iter %d: Get after race returned %v (corrupted ciphertext sealed under zero key?)", i, err)
			failed = true
			continue
		}
		if string(got.Value) != string(val) {
			t.Errorf("iter %d: roundtrip mismatch: got %q want %q", i, got.Value, val)
			failed = true
		}
	}
	if failed {
		t.Fatalf("vault key race detected — see individual failures above")
	}
}

func TestConcurrent_Puts(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("k%02d", i)
			if err := st.PutEnvVar(ctx, defaultScope(), name, []byte("v"), PutOpt{}); err != nil {
				t.Errorf("Put %s: %v", name, err)
			}
		}(i)
	}
	wg.Wait()
	got, err := st.ListEnvVars(ctx, defaultScope())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("List len = %d, want 32", len(got))
	}
}
