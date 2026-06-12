package privsep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round-trip: a written record reads back the same UID, the file is 0444, and
// its content is the decimal UID.
func TestOwnerRecord_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	const want = 501

	if err := WriteOwnerRecord(path, want); err != nil {
		t.Fatalf("WriteOwnerRecord: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != ownerRecordMode {
		t.Fatalf("mode = %o, want %o", got, ownerRecordMode)
	}

	got, err := ReadOwnerRecord(path)
	if err != nil {
		t.Fatalf("ReadOwnerRecord: %v", err)
	}
	if got != want {
		t.Fatalf("ReadOwnerRecord = %d, want %d", got, want)
	}

	// Content is the decimal UID (trailing newline tolerated).
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if strings.TrimSpace(string(data)) != "501" {
		t.Fatalf("raw content = %q, want \"501\"", string(data))
	}
}

// WriteOwnerRecord overwrites an existing record atomically and leaves no
// .owner.tmp* turds behind in the directory.
func TestOwnerRecord_OverwriteNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owner")
	if err := WriteOwnerRecord(path, 1000); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteOwnerRecord(path, 1234); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := ReadOwnerRecord(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got != 1234 {
		t.Fatalf("read = %d, want 1234", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".owner.tmp") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
}

// WriteOwnerRecord refuses a non-positive UID: recording uid 0 would allowlist
// root, defeating privsep.
func TestWriteOwnerRecord_RejectsNonPositive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	for _, uid := range []int{0, -1} {
		if err := WriteOwnerRecord(path, uid); err == nil {
			t.Fatalf("WriteOwnerRecord(%d) = nil, want error", uid)
		}
		if _, statErr := os.Stat(path); statErr == nil {
			t.Fatalf("WriteOwnerRecord(%d) created a file; want none", uid)
		}
	}
}

// WriteOwnerRecord surfaces an error when the parent directory does not exist
// (it is `byn setup`'s job to create it while privileged).
func TestWriteOwnerRecord_MissingParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", "owner")
	if err := WriteOwnerRecord(path, 501); err == nil {
		t.Fatal("WriteOwnerRecord with missing parent dir = nil, want error")
	}
}

// ReadOwnerRecord errors clearly on a missing record (the daemon turns this
// into "not provisioned").
func TestReadOwnerRecord_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	if _, err := ReadOwnerRecord(path); err == nil {
		t.Fatal("ReadOwnerRecord(missing) = nil, want error")
	}
}

// ReadOwnerRecord rejects empty / zero / garbage content. Every malformed case
// is an error, never a silently-accepted UID.
func TestReadOwnerRecord_Rejects(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"whitespace": "   \n",
		"zero":       "0\n",
		"negative":   "-1\n",
		"garbage":    "not-a-number\n",
		"trailing":   "501 502\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "owner")
			if err := os.WriteFile(path, []byte(content), 0o444); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := ReadOwnerRecord(path); err == nil {
				t.Fatalf("ReadOwnerRecord(%q) = nil, want error", content)
			}
		})
	}
}
