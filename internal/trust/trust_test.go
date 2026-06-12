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

func TestHash_Deterministic(t *testing.T) {
	a := Hash([]byte("hello"))
	if a != Hash([]byte("hello")) {
		t.Fatal("Hash is not deterministic")
	}
	if a == Hash([]byte("world")) {
		t.Fatal("different content hashed to the same value")
	}
	if len(a) != 64 {
		t.Fatalf("Hash len = %d, want 64 (sha256 hex)", len(a))
	}
}

func TestCanonicalize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Canonicalize(p); !filepath.IsAbs(got) {
		t.Fatalf("existing file: %q not absolute", got)
	}
	// A missing file still resolves to an absolute path (Abs fallback).
	if got := Canonicalize(filepath.Join(dir, "missing")); !filepath.IsAbs(got) {
		t.Fatalf("missing file: %q not absolute", got)
	}
}

func TestStat_String(t *testing.T) {
	for s, want := range map[Stat]string{
		StatusTrusted:   "trusted",
		StatusChanged:   "changed",
		StatusUntrusted: "untrusted",
	} {
		if got := s.String(); got != want {
			t.Errorf("Stat(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestStatus(t *testing.T) {
	dir := t.TempDir()
	// Use Put (the authoritative writer) to seed a record — Grant was removed.
	if _, err := Put(dir, Record{Path: "/a/.byn", SHA256: "hash1"}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		path string
		hash string
		want Stat
	}{
		{"trusted matches", "/a/.byn", "hash1", StatusTrusted},
		{"known path, changed content", "/a/.byn", "hashX", StatusChanged},
		{"unknown path", "/b/.byn", "whatever", StatusUntrusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Status(dir, c.path, c.hash)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("Status = %v, want %v", got, c.want)
			}
		})
	}
}
