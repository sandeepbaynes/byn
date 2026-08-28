package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Recording what a run of `byn exec` was given.
//
// The question this answers is asked after the fact: months later, which values
// did that process actually hold, from which .byn, run by what, and when.
//
// A run stores REFERENCES, never copies. Copying would put every secret in a
// second place and grow without bound; worse, it would quietly turn the audit
// trail into an archive of every secret the project has ever had, so a
// credential rotated after a leak would stay recoverable from the vault for
// ever. byn does not do that on its own.
//
// So a reference is (entry_id, digest): which entry, and which stored blob it
// was at the time. The digest is over the CIPHERTEXT, which carries a fresh
// nonce on every write — so it changes whenever the value is rewritten, and it
// cannot be used to confirm a guess at the plaintext.
//
// What that buys, and what it does not:
//   - Which names a run received, when, from which .byn, and run by what:
//     always answerable.
//   - The value itself: readable while it is still the value in the vault, with
//     the vault key. Once it has been replaced, byn reports that the run used a
//     value that has since changed, and says the old one was not retained —
//     rather than pretending, or keeping every superseded secret to avoid
//     having to say it.
//
// Values are never reachable from here without the vault key.

// EntryRef points at one entry as it stood for a run.
type EntryRef struct {
	EntryID int64
	// Digest identifies the stored blob — hex SHA-256 of the ciphertext, which
	// changes on every write because the nonce does. Comparing it to the entry
	// as it stands now says whether the value has changed since the run.
	Digest string
}

// ExecRunMeta is what byn knows about the caller of a run.
type ExecRunMeta struct {
	BynPath string
	Command string
	// CallerPID is the process that asked; CallerAgent is the identity byn
	// resolved above it (the agent or shell), which is what survives across the
	// short-lived processes a harness spawns per command.
	CallerPID   int
	CallerComm  string
	CallerAgent int
	CallerCwd   string
}

// ExecRun is one recorded run.
type ExecRun struct {
	ID         int64
	At         time.Time
	SnapshotID int64
	Meta       ExecRunMeta
	// VarCount is how many values the run was given, resolved from its snapshot.
	VarCount int
}

// RecordExecRun stores which values a run received, as references.
//
// names is what was actually injected. The snapshot is written as a diff
// against the most recent one for the same scope, and reused outright when
// nothing has changed — so a dev server restarted fifty times costs fifty run
// rows and one snapshot.
//
// Best-effort by contract: recording must never fail a run that byn has already
// authorized. A caller logs the error and carries on.
func (s *Store) RecordExecRun(ctx context.Context, scope Scope, meta ExecRunMeta, names []string) (int64, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return 0, err
	}
	current, err := s.entryRefs(ctx, projectID, envID, names)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	parentID, parentRefs, err := latestSnapshot(ctx, tx, projectID, envID)
	if err != nil {
		return 0, err
	}
	snapshotID := parentID
	if parentID == 0 || !sameRefs(parentRefs, current) {
		snapshotID, err = writeSnapshotDiff(ctx, tx, projectID, envID, parentID, parentRefs, current)
		if err != nil {
			return 0, err
		}
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO exec_runs (at, snapshot_id, byn_path, command,
		                        caller_pid, caller_comm, caller_agent, caller_cwd)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		nowUnix(), snapshotID, meta.BynPath, meta.Command,
		int64(meta.CallerPID), meta.CallerComm, int64(meta.CallerAgent), meta.CallerCwd)
	if err != nil {
		return 0, err
	}
	runID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return runID, tx.Commit()
}

// entryRefs resolves names to their current (entry_id, latest version_no).
//
// A name with no value is simply absent: the run did not receive it, and
// recording it as present-but-empty would misdescribe what the process held.
func (s *Store) entryRefs(ctx context.Context, projectID, envID int64, names []string) (map[string]EntryRef, error) {
	out := make(map[string]EntryRef, len(names))
	for _, n := range names {
		var id int64
		var ct []byte
		err := s.db.QueryRowContext(ctx,
			`SELECT id, value FROM entries
			  WHERE project_id = ? AND env_id = ? AND name = ? AND kind = 'env_var'`,
			projectID, envID, n).Scan(&id, &ct)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue // not present in this scope; the run did not get it
		case err != nil:
			return nil, err
		}
		out[n] = EntryRef{EntryID: id, Digest: blobDigest(ct)}
	}
	return out, nil
}

// latestSnapshot returns the most recent snapshot for a scope and its resolved
// contents, or (0, nil) when there is none yet.
func latestSnapshot(ctx context.Context, tx *sql.Tx, projectID, envID int64) (int64, map[string]EntryRef, error) {
	var id int64
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM env_snapshots WHERE project_id = ? AND env_id = ? ORDER BY id DESC LIMIT 1`,
		projectID, envID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	refs, err := resolveSnapshotTx(ctx, tx, id)
	if err != nil {
		return 0, nil, err
	}
	return id, refs, nil
}

// writeSnapshotDiff records only what differs from the parent.
func writeSnapshotDiff(ctx context.Context, tx *sql.Tx, projectID, envID, parentID int64,
	parent, current map[string]EntryRef) (int64, error) {

	var parentArg any
	if parentID != 0 {
		parentArg = parentID
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO env_snapshots (parent_id, project_id, env_id, created_at) VALUES (?, ?, ?, ?)`,
		parentArg, projectID, envID, nowUnix())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for name, ref := range current {
		if p, ok := parent[name]; ok && p == ref {
			continue // unchanged: the parent already says it
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO env_snapshot_entries (snapshot_id, name, entry_id, digest, change)
			 VALUES (?, ?, ?, ?, 'set')`,
			id, name, ref.EntryID, ref.Digest); err != nil {
			return 0, err
		}
	}
	// A name the parent had and this run did not is recorded as removed, or
	// resolving the chain would keep handing it forward for ever.
	for name := range parent {
		if _, ok := current[name]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO env_snapshot_entries (snapshot_id, name, entry_id, digest, change)
			 VALUES (?, ?, NULL, NULL, 'removed')`, id, name); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// ResolveSnapshot returns what a snapshot names, walking its parents.
func (s *Store) ResolveSnapshot(ctx context.Context, snapshotID int64) (map[string]EntryRef, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return resolveSnapshotTx(ctx, tx, snapshotID)
}

// resolveSnapshotTx walks from the root down, applying each diff in turn.
//
// Oldest first: a later snapshot's entry must overwrite an earlier one, and a
// removal must erase what an ancestor set.
func resolveSnapshotTx(ctx context.Context, tx *sql.Tx, snapshotID int64) (map[string]EntryRef, error) {
	var chain []int64
	seen := make(map[int64]bool)
	for id := snapshotID; id != 0; {
		if seen[id] {
			return nil, fmt.Errorf("vault: snapshot %d is its own ancestor", id)
		}
		seen[id] = true
		chain = append(chain, id)
		var parent sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT parent_id FROM env_snapshots WHERE id = ?`, id).Scan(&parent); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				break
			}
			return nil, err
		}
		if !parent.Valid {
			break
		}
		id = parent.Int64
	}

	out := make(map[string]EntryRef)
	for i := len(chain) - 1; i >= 0; i-- {
		rows, err := tx.QueryContext(ctx,
			`SELECT name, entry_id, digest, change FROM env_snapshot_entries WHERE snapshot_id = ?`,
			chain[i])
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var name, change string
			var entryID sql.NullInt64
			var digest sql.NullString
			if err := rows.Scan(&name, &entryID, &digest, &change); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if change == "removed" {
				delete(out, name)
				continue
			}
			out[name] = EntryRef{EntryID: entryID.Int64, Digest: digest.String}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close()
	}
	return out, nil
}

// ListExecRuns returns recorded runs, newest first.
func (s *Store) ListExecRuns(ctx context.Context, limit int) ([]ExecRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, COALESCE(snapshot_id, 0), COALESCE(byn_path,''), COALESCE(command,''),
		        COALESCE(caller_pid,0), COALESCE(caller_comm,''), COALESCE(caller_agent,0),
		        COALESCE(caller_cwd,'')
		   FROM exec_runs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []ExecRun
	for rows.Next() {
		var r ExecRun
		var at int64
		if err := rows.Scan(&r.ID, &at, &r.SnapshotID, &r.Meta.BynPath, &r.Meta.Command,
			&r.Meta.CallerPID, &r.Meta.CallerComm, &r.Meta.CallerAgent, &r.Meta.CallerCwd); err != nil {
			return nil, err
		}
		r.At = time.Unix(at, 0).UTC()
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].SnapshotID == 0 {
			continue
		}
		refs, rerr := s.ResolveSnapshot(ctx, out[i].SnapshotID)
		if rerr != nil {
			continue
		}
		out[i].VarCount = len(refs)
	}
	return out, nil
}

// SnapshotNames lists what a snapshot names, sorted. Names only — no values.
func (s *Store) SnapshotNames(ctx context.Context, snapshotID int64) ([]string, error) {
	refs, err := s.ResolveSnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for n := range refs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// OpenSnapshotValue decrypts one referenced version.
//
// This is the only path from a recorded run to a secret, and it needs the vault
// key — so the audit trail can be read for what and when without it becoming a
// second way to read values.
func (s *Store) OpenSnapshotValue(ctx context.Context, snapshotID int64, name string) ([]byte, error) {
	refs, err := s.ResolveSnapshot(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	ref, ok := refs[name]
	if !ok {
		return nil, ErrNotFound
	}
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)

	var ct []byte
	var aadVersion int
	var projectID, envID int64
	err = s.db.QueryRowContext(ctx,
		`SELECT value, aad_version, project_id, env_id FROM entries WHERE id = ?`,
		ref.EntryID).Scan(&ct, &aadVersion, &projectID, &envID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// The value must be the one the run actually held. byn does not keep
	// superseded secrets, so if it has been rewritten since, say so plainly
	// rather than hand back today's value as though it were that run's.
	if blobDigest(ct) != ref.Digest {
		return nil, ErrValueSuperseded
	}
	return s.openEntry(vk, aadVersion, projectID, envID, kindAADEnvVar, name, ct)
}

// ErrValueSuperseded means a run referenced a value that has since been
// replaced. byn does not retain the old one — an audit trail that kept every
// superseded secret would leave a credential recoverable long after it was
// rotated away.
var ErrValueSuperseded = errors.New("vault: the value used by this run has since been replaced and was not retained")

// blobDigest identifies a stored ciphertext. Over the ciphertext, not the
// plaintext: the nonce makes it change on every write, and it cannot be used to
// confirm a guess at the value.
func blobDigest(ct []byte) string {
	sum := sha256.Sum256(ct)
	return hex.EncodeToString(sum[:])
}

// sameRefs reports whether two resolved snapshots name exactly the same
// versions — the test for "nothing has changed, reuse the snapshot".
func sameRefs(a, b map[string]EntryRef) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if o, ok := b[k]; !ok || o != v {
			return false
		}
	}
	return true
}
