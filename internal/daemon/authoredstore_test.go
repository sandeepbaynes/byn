package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// An unreadable registry must never be replaced by a write that could not read
// it.
//
// The first version returned nil for both "no file" and "cannot parse it", so
// one bad read turned the next write into a wipe: it loaded nothing, appended
// its own entry, and saved a registry of one. Every caller that had stored a
// value earlier silently lost access to it, on an ordinary write. That is the
// report that found this — after the write, the registry held exactly the value
// the write had created.
//
// Losing this file costs people access to their own values, so a failed read
// must not be a licence to overwrite.
func TestAuthoredStore_UnreadableRegistryIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	a := newAuthoredStore(dir)
	first := authoredKey{Vault: "v", Project: "p", Env: "e", Name: "FIRST"}
	if err := a.Record(first, []procRef{{PID: 2, Start: 3}}, true, true); err != nil {
		t.Fatalf("record: %v", err)
	}

	// A truncated write, a half-flushed file, a format from another version.
	path := filepath.Join(dir, authoredFilename)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	second := authoredKey{Vault: "v", Project: "p", Env: "e", Name: "SECOND"}
	if err := a.Record(second, []procRef{{PID: 2, Start: 3}}, true, true); err == nil {
		t.Error("recording onto an unreadable registry should refuse, not overwrite it")
	}
	// The damaged file is still there to be recovered, not replaced by one entry.
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("the registry was removed: %v", rerr)
	}
	if string(b) != "{not json" {
		t.Errorf("the unreadable registry was rewritten as %q", string(b))
	}
	// And a caller asking about it is told nothing rather than told "yours".
	if _, ok := a.Lookup(first); ok {
		t.Error("an unreadable registry must grant nothing")
	}
}

// A missing registry is simply empty — the case that must keep working.
func TestAuthoredStore_MissingRegistryIsEmptyNotAnError(t *testing.T) {
	a := newAuthoredStore(t.TempDir())
	if names := a.NamesFor("v", "p", "e"); len(names) != 0 {
		t.Errorf("names = %v, want none", names)
	}
	k := authoredKey{Vault: "v", Project: "p", Env: "e", Name: "N"}
	if err := a.Record(k, []procRef{{PID: 2, Start: 3}}, true, true); err != nil {
		t.Errorf("recording into a fresh registry: %v", err)
	}
}

// An entry written by an older byn must keep its meaning.
//
// That version stored a single parent rather than a chain, and recorded "stored
// under the authored key" in a field called `locked`. Read by a later byn those
// became no chain and a flat false — which reads as "this is not yours", so
// upgrading silently took people's own values away from them.
func TestAuthoredStore_UpgradesAnEntryFromAnOlderByn(t *testing.T) {
	dir := t.TempDir()
	old := `[{"key":{"vault":"v","project":"p","env":"e","name":"OLD"},` +
		`"origin_pid":42,"origin_start":7,"at_unix_nano":123,"locked":true}]`
	if err := os.WriteFile(filepath.Join(dir, authoredFilename), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newAuthoredStore(dir)
	e, ok := a.Lookup(authoredKey{Vault: "v", Project: "p", Env: "e", Name: "OLD"})
	if !ok {
		t.Fatal("an entry from an older byn was not found at all")
	}
	if len(e.Chain) != 1 || e.Chain[0].PID != 42 || e.Chain[0].Start != 7 {
		t.Errorf("chain = %v, want the recorded parent carried forward", e.Chain)
	}
	if !e.Authored || !e.Unattended {
		t.Errorf("authored=%v unattended=%v; `locked` meant both, and losing that "+
			"takes the value away from whoever stored it", e.Authored, e.Unattended)
	}
}
