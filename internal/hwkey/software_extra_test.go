package hwkey

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSoftwareKey_WrongSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, []byte("short"), softwareKeyFileMode); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := loadSoftwareKey(path)
	if err == nil || !strings.Contains(err.Error(), "wrong size") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadSoftwareKey_Missing(t *testing.T) {
	_, err := loadSoftwareKey(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateOrLoad_MkdirAllError(t *testing.T) {
	// Point at a path under a regular file so MkdirAll fails.
	td := t.TempDir()
	blocker := filepath.Join(td, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewSoftware(filepath.Join(blocker, "subdir", "key"))
	err := s.CreateOrLoad()
	if err == nil {
		t.Fatal("expected mkdir err")
	}
}

func TestWriteSoftwareKey_BadDir(t *testing.T) {
	err := writeSoftwareKey("/no/such/dir/key", make([]byte, 32))
	if err == nil {
		t.Fatal("expected err")
	}
}
