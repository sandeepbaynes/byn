package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInit_RejectsNilPassword(t *testing.T) {
	_, err := Init(context.Background(), t.TempDir(), DefaultVaultName, nil)
	if err == nil {
		t.Fatal("expected err for nil password")
	}
}

func TestInit_BadRoot(t *testing.T) {
	// MkdirAll fails if root is under a regular file.
	td := t.TempDir()
	blocker := filepath.Join(td, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Init(context.Background(), filepath.Join(blocker, "vaults"), DefaultVaultName, []byte("pw"))
	if err == nil {
		t.Fatal("expected mkdir err")
	}
}

func TestInit_PreExistingFilesRefusedSecondTime(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw")); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	// Second Init at same root → ErrAlreadyInit.
	_, err := Init(context.Background(), dir, DefaultVaultName, []byte("pw"))
	if !errors.Is(err, ErrAlreadyInit) {
		t.Fatalf("err = %v, want ErrAlreadyInit", err)
	}
}

func TestPutEnvVar_OversizedValueRejected(t *testing.T) {
	st, _ := newOpenedVault(t)
	big := make([]byte, MaxValueLen+1)
	err := st.PutEnvVar(context.Background(), defaultScope(), "k", big, PutOpt{})
	if err == nil {
		t.Fatal("expected size err")
	}
}

func TestDeleteEnvVar_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.DeleteEnvVar(context.Background(), defaultScope(), "ghost")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteEnvVar_BadScope(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.DeleteEnvVar(context.Background(), Scope{}, "k")
	if err == nil {
		t.Fatal("expected bad-scope err")
	}
}

func TestDeleteEnvVar_BadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.DeleteEnvVar(context.Background(), defaultScope(), "")
	if err == nil {
		t.Fatal("expected bad-name err")
	}
}

func TestRenameEnvVar_BadScope(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameEnvVar(context.Background(), Scope{}, "a", "b"); err == nil {
		t.Fatal("expected err")
	}
}

func TestRenameEnvVar_BadNames(t *testing.T) {
	st, _ := newOpenedVault(t)
	if err := st.RenameEnvVar(context.Background(), defaultScope(), "", "b"); err == nil {
		t.Fatal("empty old")
	}
	if err := st.RenameEnvVar(context.Background(), defaultScope(), "a", ""); err == nil {
		t.Fatal("empty new")
	}
}

func TestRenameEnvVar_SameNameNoop(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := st.RenameEnvVar(ctx, defaultScope(), "k", "k"); err != nil {
		t.Fatalf("noop: %v", err)
	}
}

func TestRenameEnvVar_RequiresUnlock(t *testing.T) {
	st, _ := newOpenedVault(t)
	ctx := context.Background()
	if err := st.PutEnvVar(ctx, defaultScope(), "k", []byte("v"), PutOpt{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	st.Lock()
	err := st.RenameEnvVar(ctx, defaultScope(), "k", "k2")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
}

func TestRenameEnvVar_NotFound(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.RenameEnvVar(context.Background(), defaultScope(), "ghost", "new")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetEnvVar_BadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	_, err := st.GetEnvVar(context.Background(), defaultScope(), "")
	if err == nil {
		t.Fatal("expected err")
	}
}

func TestListEnvVars_BadScope(t *testing.T) {
	st, _ := newOpenedVault(t)
	_, err := st.ListEnvVars(context.Background(), Scope{})
	if err == nil {
		t.Fatal("expected err")
	}
}

func TestCreateProject_BadName(t *testing.T) {
	st, _ := newOpenedVault(t)
	err := st.CreateProject(context.Background(), "")
	if err == nil {
		t.Fatal("expected err")
	}
}
