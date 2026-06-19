// Package audit provides a per-vault, append-only, HMAC-chained audit
// log writer.
//
// Each event is one JSON line on disk. The HMAC chain links events
// together so that:
//
//   - inserting a forged event fails verification (HMAC depends on
//     the prior hmac_chain value plus the event bytes)
//   - deleting an event leaves a chain break (the next-after-deleted
//     entry's hmac_chain references a value the verifier can't
//     reproduce)
//   - truncating the file leaves the in-DB head pointing at a value
//     not present anywhere on disk
//
// The chain seed is stored in meta(audit_chain_seed); the latest
// hmac_chain is mirrored to meta(audit_chain_head). On every Append,
// both the on-disk JSON line and the DB head are updated in the same
// (vault, time) order. A crash between the write and the DB update
// leaves the chain head one entry behind — New() reconciles this on
// startup by re-reading the last on-disk line (see lastDiskHead).
//
// Files: <root>/audit/<vault>/YYYY-MM.log, mode 0600, O_APPEND. The
// per-vault subdir keeps verification simple (each chain is one
// vault's events) and lets a vault delete drop the audit subtree too.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one row in the audit log. Field ordering matters for the
// HMAC computation — see eventBytes.
type Event struct {
	TS            int64         `json:"ts"`                // unix nanoseconds
	VaultID       string        `json:"vault_id"`          // matches meta.vault_id
	VaultName     string        `json:"vault_name"`        // for human reading
	Project       string        `json:"project,omitempty"` // scope at time of op
	Env           string        `json:"env,omitempty"`
	Kind          string        `json:"kind,omitempty"`       // env_var | file
	EntryName     string        `json:"entry_name,omitempty"` // plain name (user decision)
	BynPath       string        `json:"byn_path,omitempty"`   // authorizing .byn for an exec injection
	Command       string        `json:"command,omitempty"`    // the exec'd command the injection ran
	Op            string        `json:"op"`                   // ipc op string, e.g., "put"
	Outcome       string        `json:"outcome"`              // "ok" | "denied" | "not_found" | "error"
	CallerUID     uint32        `json:"caller_uid,omitempty"`
	CallerPID     int           `json:"caller_pid,omitempty"`
	CallerComm    string        `json:"caller_comm,omitempty"`    // process name of the caller PID
	CallerPComm   string        `json:"caller_pcomm,omitempty"`   // parent process name (who invoked it)
	CallerSurface string        `json:"caller_surface,omitempty"` // "socket" (cli/tui) | "portal" (browser)
	ErrorCode     string        `json:"error_code,omitempty"`     // ipc error code if any
	Reseal        *ResealMarker `json:"reseal,omitempty"`         // present only on reseal marker events
	HMACChain     string        `json:"hmac_chain"`               // hex; depends on prev_hmac + event
}

// ResealMarker is the payload of a reseal marker event. It records an
// owner-acknowledged audit-chain discontinuity: VerifyChain treats a valid
// marker as a legitimate chain-restart point at observed_head. The marker's own
// hmac_chain continues the chain normally, so it is unforgeable without the seed.
type ResealMarker struct {
	BrokenIndex  int    `json:"broken_index"`  // 0-based index of the first post-break event
	ObservedHead string `json:"observed_head"` // recorded hmac at the break (the restart anchor)
	ExpectedHead string `json:"expected_head"` // hmac verification expected there (forensic)
	Reason       string `json:"reason"`        // free-text, owner-supplied
	By           string `json:"by"`            // who acknowledged (owner / session)
}

// ErrNoBreak is returned by Reseal when the chain has no un-acknowledged break.
var ErrNoBreak = errors.New("audit: no un-acknowledged chain break to reseal")

// Outcome constants for the Outcome field.
const (
	OutcomeOK       = "ok"
	OutcomeDenied   = "denied"
	OutcomeNotFound = "not_found"
	OutcomeError    = "error"
)

// chainHeadStore is the subset of vault.Store this package needs.
// Keeping it as an interface lets tests inject a fake store without
// dragging the SQLite dependency in.
type chainHeadStore interface {
	MetaGet(ctx context.Context, key string) (string, error)
	MetaSet(ctx context.Context, key, value string) error
}

// Logger is the per-vault audit log writer. Instances are safe for
// concurrent Append from multiple goroutines.
type Logger struct {
	rootDir   string
	vaultID   string
	vaultName string
	store     chainHeadStore

	mu      sync.Mutex
	seed    []byte // hex-decoded HMAC key
	prevHex string // current head HMAC, hex-encoded
}

// MetaKeySeed and MetaKeyHead are the meta-table keys this package
// reads and writes. They're re-exported as constants here so callers
// don't need to import vault to set them up — but they MUST match
// vault.MetaKeyAuditChainSeed / vault.MetaKeyAuditChainHead. Tests
// verify the lockstep.
const (
	MetaKeySeed = "audit_chain_seed"
	MetaKeyHead = "audit_chain_head"
)

// New constructs a Logger for a vault. The HMAC seed is read from
// store.MetaGet at construction time; if missing or malformed, New
// returns an error so the daemon refuses to start without working
// audit (rather than silently degrading).
func New(ctx context.Context, rootDir, vaultID, vaultName string, store chainHeadStore) (*Logger, error) {
	if store == nil {
		return nil, errors.New("audit: nil store")
	}
	if vaultID == "" || vaultName == "" {
		return nil, errors.New("audit: empty vault id or name")
	}
	seedHex, err := store.MetaGet(ctx, MetaKeySeed)
	if err != nil {
		return nil, fmt.Errorf("audit: read seed: %w", err)
	}
	if seedHex == "" {
		return nil, errors.New("audit: chain seed missing from meta (init should have set it)")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("audit: bad seed length %d (want 32)", len(seed))
	}
	head, err := store.MetaGet(ctx, MetaKeyHead)
	if err != nil {
		return nil, fmt.Errorf("audit: read head: %w", err)
	}
	dir := filepath.Join(rootDir, "audit", vaultName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	// Reconcile the head with the durable on-disk log. Append writes the on-disk
	// line BEFORE updating the meta head; a crash in that window leaves meta one
	// entry behind. The on-disk last line is the source of truth — adopt it and
	// re-persist meta, so the next Append chains correctly. This is the repair
	// this file's header documents.
	if diskHead, ok, derr := lastDiskHead(dir); derr != nil {
		return nil, fmt.Errorf("audit: scan last line: %w", derr)
	} else if ok && diskHead != head {
		if err := store.MetaSet(ctx, MetaKeyHead, diskHead); err != nil {
			return nil, fmt.Errorf("audit: reconcile head: %w", err)
		}
		head = diskHead
	}
	return &Logger{
		rootDir:   rootDir,
		vaultID:   vaultID,
		vaultName: vaultName,
		store:     store,
		seed:      seed,
		prevHex:   head,
	}, nil
}

// lastDiskHead returns the hmac_chain of the last parseable line in the vault's
// audit log dir (newest file first, scanning lines bottom-up), skipping a torn
// trailing line a partial write may have left. ok is false when no parseable
// line exists yet (fresh/empty log).
func lastDiskHead(dir string) (head string, ok bool, err error) {
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read dir: %w", rerr)
	}
	files := make([]string, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			files = append(files, ent.Name())
		}
	}
	sortStrings(files)
	for i := len(files) - 1; i >= 0; i-- {
		raw, rerr := os.ReadFile(filepath.Join(dir, files[i])) // #nosec G304 -- daemon-controlled
		if rerr != nil {
			return "", false, fmt.Errorf("read %s: %w", files[i], rerr)
		}
		lines := splitLines(raw)
		for j := len(lines) - 1; j >= 0; j-- {
			if len(lines[j]) == 0 {
				continue
			}
			var e Event
			if json.Unmarshal(lines[j], &e) != nil {
				continue // torn / partial line — walk back
			}
			if e.HMACChain == "" {
				continue
			}
			return e.HMACChain, true, nil
		}
	}
	return "", false, nil
}

// Append writes an event to the current month's log file and updates
// the chain head. Returns the computed hmac_chain so the caller can
// surface it (e.g., for tests).
//
// The TS, VaultID, VaultName, and HMACChain fields are overwritten by
// Append; callers should leave them zero/empty in the supplied event.
func (l *Logger) Append(ctx context.Context, e Event) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(ctx, e)
}

// appendLocked writes an event and advances the chain head. Caller holds l.mu.
// Shared by Append and by Reseal (which appends a marker event).
func (l *Logger) appendLocked(ctx context.Context, e Event) (string, error) {
	e.TS = time.Now().UTC().UnixNano()
	e.VaultID = l.vaultID
	e.VaultName = l.vaultName
	e.HMACChain = "" // zeroed before HMAC computation

	chainHex, err := l.computeChain(e)
	if err != nil {
		return "", err
	}
	e.HMACChain = chainHex

	line, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("audit: marshal event: %w", err)
	}
	line = append(line, '\n')

	if err := l.appendLine(time.Unix(0, e.TS).UTC(), line); err != nil {
		return "", err
	}

	// Update DB head AFTER the disk write succeeds. A crash between
	// the two leaves the on-disk line in place and the DB head one
	// behind — New() reconciles it from the last on-disk line on restart.
	if err := l.store.MetaSet(ctx, MetaKeyHead, chainHex); err != nil {
		return "", fmt.Errorf("audit: update head: %w", err)
	}
	l.prevHex = chainHex
	return chainHex, nil
}

// Head returns the current chain head as a hex string. Empty when the
// log has never been written.
func (l *Logger) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prevHex
}

// computeChain returns the HMAC for the next event given the current
// prev. Caller holds l.mu.
func (l *Logger) computeChain(e Event) (string, error) {
	buf, err := eventBytes(e)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, l.seed)
	if l.prevHex != "" {
		prev, err := hex.DecodeString(l.prevHex)
		if err != nil {
			return "", fmt.Errorf("audit: prev head malformed: %w", err)
		}
		mac.Write(prev)
	}
	mac.Write(buf)
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// eventBytes returns the canonical byte representation of an event
// used for chain computation: JSON with HMACChain forced empty, sorted
// keys (json.Marshal in Go is deterministic for structs).
func eventBytes(e Event) ([]byte, error) {
	e.HMACChain = ""
	return json.Marshal(e)
}

// appendLine writes line to the YYYY-MM.log for the given timestamp.
// Caller holds l.mu.
func (l *Logger) appendLine(when time.Time, line []byte) error {
	fname := filepath.Join(l.rootDir, "audit", l.vaultName, when.Format("2006-01")+".log")
	f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- path is daemon-controlled
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", fname, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("audit: write %s: %w", fname, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("audit: sync %s: %w", fname, err)
	}
	return nil
}

// auditLines reads every non-empty line of the vault's audit log in
// chronological order (files sorted by YYYY-MM). Caller holds l.mu.
func (l *Logger) auditLines() ([][]byte, error) {
	dir := filepath.Join(l.rootDir, "audit", l.vaultName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			files = append(files, ent.Name())
		}
	}
	sortStrings(files)
	var out [][]byte
	for _, fname := range files {
		raw, rerr := os.ReadFile(filepath.Join(dir, fname)) // #nosec G304 -- daemon-controlled
		if rerr != nil {
			return nil, fmt.Errorf("audit: read %s: %w", fname, rerr)
		}
		for _, line := range splitLines(raw) {
			if len(line) > 0 {
				out = append(out, line)
			}
		}
	}
	return out, nil
}

// chainWalk is the result of a marker-aware chain verification.
type chainWalk struct {
	badIndex int    // index of the first UN-acknowledged break, or -1 if none
	total    int    // events walked
	acked    int    // acknowledged reseal restarts honored
	observed string // recorded hmac at badIndex (hex), "" when intact
	expected string // expected hmac at badIndex (hex), "" when intact
}

// walkChainLocked verifies the chain, tolerating a break that a valid reseal
// marker acknowledges (the bridge model). Caller holds l.mu.
func (l *Logger) walkChainLocked() (chainWalk, error) {
	lines, err := l.auditLines()
	if err != nil {
		return chainWalk{badIndex: -1}, err
	}
	// Pass 1: collect reseal markers, keyed on the head they acknowledge.
	ackByObserved := map[string]*ResealMarker{}
	for _, line := range lines {
		var e Event
		if json.Unmarshal(line, &e) != nil {
			continue // torn line — pass 2 surfaces it as an error
		}
		if e.Reseal != nil {
			ackByObserved[e.Reseal.ObservedHead] = e.Reseal
		}
	}
	// Pass 2: walk, honoring acknowledged restarts.
	prev := []byte(nil)
	idx, acked := 0, 0
	for _, line := range lines {
		var e Event
		if jerr := json.Unmarshal(line, &e); jerr != nil {
			return chainWalk{badIndex: idx, total: idx, acked: acked}, fmt.Errorf("audit: parse line %d: %w", idx, jerr)
		}
		recorded, derr := hex.DecodeString(e.HMACChain)
		if derr != nil {
			return chainWalk{badIndex: idx, total: idx, acked: acked}, fmt.Errorf("audit: parse hmac at line %d: %w", idx, derr)
		}
		expected, eerr := computeWithSeed(l.seed, prev, e)
		if eerr != nil {
			return chainWalk{badIndex: idx, total: idx, acked: acked}, eerr
		}
		if !hmac.Equal(recorded, expected) {
			// Acknowledged iff a marker records EXACTLY this observed (recorded)
			// head and the expected head we just computed. A forged marker fails at
			// its own line below (it can't be signed without the seed).
			if m := ackByObserved[e.HMACChain]; m != nil && m.ExpectedHead == hex.EncodeToString(expected) {
				acked++
				prev = recorded
				idx++
				continue
			}
			return chainWalk{
				badIndex: idx, total: idx, acked: acked,
				observed: e.HMACChain, expected: hex.EncodeToString(expected),
			}, nil
		}
		prev = recorded
		idx++
	}
	return chainWalk{badIndex: -1, total: idx, acked: acked}, nil
}

// VerifyChain re-walks the chain, tolerating breaks acknowledged by a reseal
// marker. Returns the first un-acknowledged break index (or -1), the events
// walked, and the count of acknowledged reseals. Used by `byn doctor`.
func (l *Logger) VerifyChain(_ context.Context) (badIndex, total, acked int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, werr := l.walkChainLocked()
	return w.badIndex, w.total, w.acked, werr
}

// Reseal acknowledges the first un-acknowledged chain break by appending a
// signed bridge marker — original event hashes are never rewritten. Returns
// ErrNoBreak when the chain is intact. The caller must ensure the vault is
// unlocked (the seed is required to sign the marker).
func (l *Logger) Reseal(ctx context.Context, reason, by string) (*ResealMarker, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, err := l.walkChainLocked()
	if err != nil {
		return nil, err
	}
	if w.badIndex < 0 {
		return nil, ErrNoBreak
	}
	m := &ResealMarker{
		BrokenIndex:  w.badIndex,
		ObservedHead: w.observed,
		ExpectedHead: w.expected,
		Reason:       reason,
		By:           by,
	}
	if _, err := l.appendLocked(ctx, Event{Op: "audit.reseal", Outcome: OutcomeOK, Reseal: m}); err != nil {
		return nil, err
	}
	return m, nil
}

// Tail returns the most recent n events across all monthly log files
// in chronological order (oldest first within the returned slice).
// If n <= 0, all events are returned. Reading runs without holding
// l.mu — files are append-only and never rewritten, so a snapshot
// read is consistent.
func (l *Logger) Tail(_ context.Context, n int) ([]Event, error) {
	dir := filepath.Join(l.rootDir, "audit", l.vaultName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: read dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		files = append(files, ent.Name())
	}
	sortStrings(files)

	var all []Event
	for fi, fname := range files {
		path := filepath.Join(dir, fname)
		raw, rerr := os.ReadFile(path) // #nosec G304 -- daemon-controlled
		if rerr != nil {
			return nil, fmt.Errorf("audit: read %s: %w", path, rerr)
		}
		lines := splitLines(raw)
		// Tolerate a partial/garbled LAST line in the CURRENT month's
		// file only — a writer that crashed mid-Append could leave
		// the trailing line incomplete. Historical (older) files are
		// immutable rolls; any parse failure there is a real problem
		// and surfaces as an error.
		isCurrent := fi == len(files)-1
		for li, line := range lines {
			if len(line) == 0 {
				continue
			}
			var e Event
			if jerr := json.Unmarshal(line, &e); jerr != nil {
				if isCurrent && li == len(lines)-1 {
					// Skip the trailing partial; do not fail the whole
					// tail. Audit verify will still catch this if it's
					// a real corruption (not just a writer race).
					continue
				}
				return nil, fmt.Errorf("audit: parse %s line %d: %w", path, li, jerr)
			}
			all = append(all, e)
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

// computeWithSeed is the non-method variant used by VerifyChain to
// avoid touching l.prevHex during the walk.
func computeWithSeed(seed, prev []byte, e Event) ([]byte, error) {
	buf, err := eventBytes(e)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, seed)
	mac.Write(prev)
	mac.Write(buf)
	return mac.Sum(nil), nil
}

// splitLines returns lines without the trailing newline. Empty lines
// preserved as empty entries.
func splitLines(raw []byte) [][]byte {
	out := make([][]byte, 0, 16)
	start := 0
	for i, b := range raw {
		if b == '\n' {
			out = append(out, raw[start:i])
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

// sortStrings is a tiny bubble sort to avoid importing sort for this
// one tiny use. n is small (one entry per month).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
