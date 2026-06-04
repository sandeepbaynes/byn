package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_Missing(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Records) != 0 {
		t.Fatalf("expected empty store, got %d records", len(s.Records))
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := &Store{Records: []Record{{Path: "/a/.byn", SHA256: "abc"}, {Path: "/b/.byn", SHA256: "def"}}}
	if err := Save(dir, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(out.Records) != 2 || out.Records[0].Path != "/a/.byn" || out.Records[1].SHA256 != "def" {
		t.Fatalf("round-trip mismatch: %+v", out.Records)
	}
	info, err := os.Stat(filepath.Join(dir, Filename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, &Store{Records: []Record{{Path: "/a/.byn", SHA256: "1"}, {Path: "/b/.byn", SHA256: "2"}}}); err != nil {
		t.Fatal(err)
	}
	removed, err := Remove(dir, "/a/.byn")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Fatal("expected removed=true")
	}
	s, _ := Load(dir)
	if len(s.Records) != 1 || s.Records[0].Path != "/b/.byn" {
		t.Fatalf("after remove: %+v", s.Records)
	}

	removed, err = Remove(dir, "/not/here")
	if err != nil {
		t.Fatalf("Remove absent: %v", err)
	}
	if removed {
		t.Error("expected removed=false for an absent path")
	}
}

func TestLoad_Malformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, Filename), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected an error for a malformed store")
	}
}
