package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// The record of which variables a caller created, and who that caller was.
//
// It lives in the daemon's own state directory rather than in the trust record,
// for one decisive reason: it has to be writable while the vault is LOCKED. A
// trust record is bound by a MAC keyed from the vault key, so updating one
// needs the master password — which is exactly what an agent working unattended
// does not have, and exactly the case this exists to serve.
//
// Its integrity rests on the permissions of that directory, not on cryptography.
// That is worth stating plainly, because the obvious alternative looks stronger
// and is not: sealing the file under the machine key would be theatre, since
// byn's machine key is derived from /etc/machine-id, which every local process
// can read and therefore recompute. Under privilege separation the directory is
// mode 0700 and owned by the daemon's service user, so a process at the owner's
// uid can neither read nor rewrite this. Without privilege separation it can —
// but without privilege separation it can also read the values straight out of
// the daemon, so nothing here is the weak link.

// authoredFilename is the registry's name inside the daemon state directory.
const authoredFilename = "authored.json"

// authoredKey identifies one variable in one scope of one vault.
type authoredKey struct {
	Vault   string `json:"vault"`
	Project string `json:"project"`
	Env     string `json:"env"`
	Name    string `json:"name"`
}

// authoredEntry is who created a variable, and when.
type authoredEntry struct {
	Key authoredKey `json:"key"`
	// OriginPID and OriginStart identify the creating caller's PARENT — the
	// agent or shell that ran `byn put`, not the byn process itself, which has
	// exited long before the value is used again. The start time makes the pair
	// immune to PID reuse.
	OriginPID   int    `json:"origin_pid"`
	OriginStart uint64 `json:"origin_start"`
	// Chain is the recorded ancestry, nearest first. Two callers are the same
	// agent when their chains overlap — see originDepth in procorigin.go for
	// why a single parent is not enough.
	Chain      []procRef `json:"chain,omitempty"`
	AtUnixNano int64     `json:"at_unix_nano"`
	// Authored records that the value is stored under the scope's authored key
	// rather than the vault key — that is, that byn took it in unattended, with
	// no session and no password behind it.
	//
	// It is the line the read and replace exemptions are drawn on. A value byn
	// accepted without a credential can be handed back to its author without
	// one, because no credential ever stood between them. A value written by
	// someone who WAS authenticated was protected by that credential from the
	// start, and keeps needing it — otherwise unlocking in one terminal would
	// quietly grant reads in another, which is the thing sessions exist to stop.
	Authored bool `json:"authored,omitempty"`
	// Unattended records that no credential stood behind the write at all — no
	// session, no password, no presence token.
	//
	// Separate from Authored because the two can differ: an unattended write to
	// an OPEN vault with no trusted .byn to key it takes the ordinary path and
	// is not stored under the authored key, but it is still a value that
	// appeared without a person. This is the flag visibility hangs on. An agent
	// can silence "no value for X" by inventing one, and if that name is a real
	// secret the program starts cleanly and does the wrong thing quietly —
	// encrypting with a key nobody can reproduce, say. byn cannot tell an
	// invented value from a provisioned one, so it must at least never hide
	// which is which.
	Unattended bool `json:"unattended,omitempty"`
	// Locked is the name this carried in the first version of this file, kept
	// so an entry written then keeps its meaning. See normalize.
	Locked *bool `json:"locked,omitempty"`
}

// authoredStore is the on-disk registry. All methods are safe for concurrent
// use and tolerate a missing or unreadable file by behaving as if empty, which
// costs a caller an approval rather than granting one by accident.
type authoredStore struct {
	dir string
	mu  sync.Mutex
}

func newAuthoredStore(dir string) *authoredStore { return &authoredStore{dir: dir} }

func (a *authoredStore) path() string { return filepath.Join(a.dir, authoredFilename) }

// load reads the registry.
//
// A MISSING file is an empty registry. A file that exists and cannot be read is
// an error, and the difference matters more than it looks: the first version
// returned nil for both, so an unreadable file became "nobody has authored
// anything" — and the next write, having loaded nothing, saved only its own
// entry and destroyed every other one. Silently. That is the shape of the
// report that found this: after one write the registry held exactly the value
// that write had created, and every caller that had stored something earlier
// lost access to it.
//
// Losing this file costs people access to their own values, so it is never
// replaced on the strength of a read that did not work.
func (a *authoredStore) load() ([]authoredEntry, error) {
	b, err := os.ReadFile(a.path()) // #nosec G304 -- daemon-owned state directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no registry yet
	}
	if err != nil {
		return nil, err
	}
	var out []authoredEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("registry is unreadable: %w", err)
	}
	for i := range out {
		out[i].normalize()
	}
	return out, nil
}

// normalize upgrades an entry written by an older byn in place.
//
// The first version stored a single parent rather than a chain, and recorded
// "written under the authored key" in a field called `locked`. Read by a later
// byn those became a chain of none and a flat false, which reads as "this is
// not yours" — so upgrading silently took people's own values away from them,
// which is the opposite of what an upgrade should do.
func (e *authoredEntry) normalize() {
	if len(e.Chain) == 0 && e.OriginPID > 1 {
		e.Chain = []procRef{{PID: e.OriginPID, Start: e.OriginStart}}
	}
	if e.Locked != nil && *e.Locked {
		// `locked` meant the value was stored under the scope's authored key,
		// which only ever happened for a write with nobody behind it.
		e.Authored, e.Unattended = true, true
	}
}

// save writes the registry atomically, so a crash mid-write cannot leave a
// truncated file that reads as "nobody authored anything".
func (a *authoredStore) save(entries []authoredEntry) error {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Key != entries[j].Key {
			return authoredKeyLess(entries[i].Key, entries[j].Key)
		}
		return entries[i].AtUnixNano < entries[j].AtUnixNano
	})
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	tmp := a.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path())
}

func authoredKeyLess(x, y authoredKey) bool {
	if x.Vault != y.Vault {
		return x.Vault < y.Vault
	}
	if x.Project != y.Project {
		return x.Project < y.Project
	}
	if x.Env != y.Env {
		return x.Env < y.Env
	}
	return x.Name < y.Name
}

// Record notes that origin created key's variable, replacing any earlier entry
// for the same name.
//
// Replacing rather than keeping the first is deliberate: this is only ever
// called for a CREATE, so the name did not exist a moment ago, and whatever was
// recorded for an earlier incarnation of it describes a value that is gone.
// Letting that stand would hand its author a claim over someone else's secret.
func (a *authoredStore) Record(key authoredKey, chain []procRef, authored, unattended bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries, err := a.load()
	if err != nil {
		// Writing now would replace every other caller's authorship with this
		// one entry. Better to lose this record than all of them.
		return err
	}
	out := entries[:0:0]
	for _, e := range entries {
		if e.Key != key {
			out = append(out, e)
		}
	}
	var origin procRef
	if len(chain) > 0 {
		origin = chain[0]
	}
	out = append(out, authoredEntry{
		Key:         key,
		OriginPID:   origin.PID,
		OriginStart: origin.Start,
		Chain:       chain,
		AtUnixNano:  time.Now().UnixNano(),
		Authored:    authored,
		Unattended:  unattended,
	})
	return a.save(out)
}

// Lookup returns the authorship of key, if any.
func (a *authoredStore) Lookup(key authoredKey) (authoredEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries, err := a.load()
	if err != nil {
		return authoredEntry{}, false // unreadable → grants nothing
	}
	for _, e := range entries {
		if e.Key == key {
			return e, true
		}
	}
	return authoredEntry{}, false
}

// Forget drops authorship of the named variables in a scope.
//
// Called when the stored value stops being the author's: an overwrite by
// someone holding the password, a delete, or a rename. Without it an agent
// could create a placeholder, have a person replace it with the real
// credential, and read that credential back as its own.
func (a *authoredStore) Forget(vaultName, project, env string, names ...string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries, err := a.load()
	if err != nil {
		return err // never rewrite a registry byn could not read
	}
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	out := entries[:0:0]
	changed := false
	for _, e := range entries {
		if e.Key.Vault == vaultName && e.Key.Project == project && e.Key.Env == env && drop[e.Key.Name] {
			changed = true
			continue
		}
		out = append(out, e)
	}
	if !changed {
		return nil
	}
	return a.save(out)
}

// NamesFor lists the variables recorded as authored in one scope, for display.
func (a *authoredStore) NamesFor(vaultName, project, env string) []string {
	return a.namesMatching(vaultName, project, env, func(authoredEntry) bool { return true })
}

// UnattendedNamesFor lists the variables in one scope that were stored with no
// credential behind them — the ones a person should be able to see at a glance,
// because byn cannot tell an invented value from a provisioned one.
func (a *authoredStore) UnattendedNamesFor(vaultName, project, env string) []string {
	return a.namesMatching(vaultName, project, env, func(e authoredEntry) bool { return e.Unattended })
}

func (a *authoredStore) namesMatching(vaultName, project, env string, keep func(authoredEntry) bool) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	entries, err := a.load()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Key.Vault == vaultName && e.Key.Project == project && e.Key.Env == env && keep(e) {
			out = append(out, e.Key.Name)
		}
	}
	sort.Strings(out)
	return out
}
