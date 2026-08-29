package vault

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func execRunFixture(t *testing.T) (*Store, Scope) {
	t.Helper()
	ctx := context.Background()
	st, err := Init(ctx, t.TempDir(), DefaultVaultName, []byte("pw"))
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := st.Unlock([]byte("pw")); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return st, Scope{Project: DefaultProjectName, Env: DefaultEnvName}
}

func countRows(t *testing.T, st *Store, table string) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// A run records which values it was given, and a run whose values have not
// changed writes no new snapshot.
//
// This is the whole reason snapshots are diffs: a dev server restarted fifty
// times must not put fifty copies of the same list in the vault.
func TestExecRun_UnchangedRunsShareOneSnapshot(t *testing.T) {
	ctx := context.Background()
	st, scope := execRunFixture(t)
	if err := st.PutEnvVar(ctx, scope, "A", []byte("1"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnvVar(ctx, scope, "B", []byte("2"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	names := []string{"A", "B"}
	meta := ExecRunMeta{BynPath: "/p/.byn", Command: "mytool run", CallerPID: 42}

	for i := 0; i < 5; i++ {
		if _, err := st.RecordExecRun(ctx, scope, meta, names); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if got := countRows(t, st, "exec_runs"); got != 5 {
		t.Errorf("exec_runs = %d, want 5 — every run is recorded", got)
	}
	if got := countRows(t, st, "env_snapshots"); got != 1 {
		t.Errorf("env_snapshots = %d, want 1 — identical runs must share a snapshot", got)
	}
}

// A changed value produces a new snapshot holding only what changed.
func TestExecRun_SnapshotStoresOnlyTheDifference(t *testing.T) {
	ctx := context.Background()
	st, scope := execRunFixture(t)
	for _, n := range []string{"A", "B", "C"} {
		if err := st.PutEnvVar(ctx, scope, n, []byte("v"), PutOpt{}); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"A", "B", "C"}
	meta := ExecRunMeta{BynPath: "/p/.byn"}
	if _, err := st.RecordExecRun(ctx, scope, meta, names); err != nil {
		t.Fatal(err)
	}
	first := countRows(t, st, "env_snapshot_entries")
	if first != 3 {
		t.Fatalf("first snapshot rows = %d, want 3", first)
	}

	// One value changes.
	if err := st.PutEnvVar(ctx, scope, "B", []byte("v2"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	runID, err := st.RecordExecRun(ctx, scope, meta, names)
	if err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, st, "env_snapshots"); got != 2 {
		t.Errorf("env_snapshots = %d, want 2", got)
	}
	// Three rows for the first snapshot plus ONE for the change — not four more.
	if got := countRows(t, st, "env_snapshot_entries"); got != first+1 {
		t.Errorf("snapshot entry rows = %d, want %d — only the difference should be stored",
			got, first+1)
	}

	// And the second snapshot still resolves to all three names.
	runs, err := st.ListExecRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var snap int64
	for _, r := range runs {
		if r.ID == runID {
			snap = r.SnapshotID
		}
	}
	got, err := st.SnapshotNames(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Errorf("resolved names = %v, want all three — a diff must resolve through its parent", got)
	}
}

// A name that goes away must not be resolved forward for ever.
func TestExecRun_RemovedNameDoesNotPersist(t *testing.T) {
	ctx := context.Background()
	st, scope := execRunFixture(t)
	for _, n := range []string{"A", "B"} {
		if err := st.PutEnvVar(ctx, scope, n, []byte("v"), PutOpt{}); err != nil {
			t.Fatal(err)
		}
	}
	meta := ExecRunMeta{}
	if _, err := st.RecordExecRun(ctx, scope, meta, []string{"A", "B"}); err != nil {
		t.Fatal(err)
	}
	runID, err := st.RecordExecRun(ctx, scope, meta, []string{"A"}) // B no longer injected
	if err != nil {
		t.Fatal(err)
	}
	runs, _ := st.ListExecRuns(ctx, 10)
	var snap int64
	for _, r := range runs {
		if r.ID == runID {
			snap = r.SnapshotID
		}
	}
	names, err := st.SnapshotNames(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "A" {
		t.Errorf("resolved = %v, want [A] — a name the run did not get must not carry forward", names)
	}
}

// A run's value is readable while it is still the value in the vault, and byn
// says plainly when it is not — rather than handing back today's value as
// though it were that run's, or keeping every superseded secret so it never has
// to say so. A trail that retained them would leave a credential recoverable
// long after it was rotated away.
func TestExecRun_SupersededValueIsReportedNotInvented(t *testing.T) {
	ctx := context.Background()
	st, scope := execRunFixture(t)
	if err := st.PutEnvVar(ctx, scope, "TOKEN", []byte("first"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	runID, err := st.RecordExecRun(ctx, scope, ExecRunMeta{}, []string{"TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	// The value changes after the run.
	if err := st.PutEnvVar(ctx, scope, "TOKEN", []byte("second"), PutOpt{}); err != nil {
		t.Fatal(err)
	}

	runs, _ := st.ListExecRuns(ctx, 10)
	var snap int64
	for _, r := range runs {
		if r.ID == runID {
			snap = r.SnapshotID
		}
	}
	if _, err := st.OpenSnapshotValue(ctx, snap, "TOKEN"); !errors.Is(err, ErrValueSuperseded) {
		t.Fatalf("err = %v, want ErrValueSuperseded — the run's value is gone and byn must say so", err)
	}

	// While the value is unchanged, it reads back exactly.
	second, err := st.RecordExecRun(ctx, scope, ExecRunMeta{}, []string{"TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	runs, _ = st.ListExecRuns(ctx, 10)
	for _, r := range runs {
		if r.ID == second {
			snap = r.SnapshotID
		}
	}
	got, err := st.OpenSnapshotValue(ctx, snap, "TOKEN")
	if err != nil {
		t.Fatalf("open an unchanged value: %v", err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Errorf("value = %q, want \"second\"", got)
	}
}

// Values are reachable only with the vault key. The trail says what and when
// without becoming a second way to read secrets.
func TestExecRun_ValuesNeedTheVaultKey(t *testing.T) {
	ctx := context.Background()
	st, scope := execRunFixture(t)
	if err := st.PutEnvVar(ctx, scope, "TOKEN", []byte("v"), PutOpt{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordExecRun(ctx, scope, ExecRunMeta{}, []string{"TOKEN"}); err != nil {
		t.Fatal(err)
	}
	runs, _ := st.ListExecRuns(ctx, 10)
	snap := runs[0].SnapshotID

	st.Lock()
	// Metadata still readable: that is the point of separating them.
	if names, err := st.SnapshotNames(ctx, snap); err != nil || len(names) != 1 {
		t.Errorf("names on a locked vault: %v %v — the trail should stay readable", names, err)
	}
	if _, err := st.OpenSnapshotValue(ctx, snap, "TOKEN"); err == nil {
		t.Error("a locked vault returned a recorded VALUE; only the key may open one")
	}
}

// A v6 vault must walk forward to v7 and keep the runs it already recorded.
// The column addition also has to survive being applied twice: adding it and
// recording the new version are two writes, and a machine that stops between
// them leaves a vault whose schema is ahead of its marker.
func TestMigrateV6toV7_NamesTheAgentAndIsRepeatable(t *testing.T) {
	st, dir := newOpenedVault(t)
	ctx := context.Background()
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	db, err := openDB(ctx, filepath.Join(Dir(dir, DefaultVaultName), dbFilename))
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	// Rewind to v6: a real v6 vault has no such column, and a run recorded
	// under it must still be readable afterwards.
	for _, stmt := range []string{
		`ALTER TABLE exec_runs DROP COLUMN caller_agent_comm`,
		`INSERT INTO exec_runs (at, byn_path, command, caller_pid, caller_comm, caller_agent)
		 VALUES (1, '/p/.byn', 'make dev', 42, 'byn', 7)`,
		`UPDATE meta SET value = '6' WHERE key = 'schema_version'`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("rewind (%s): %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	st2 := reopenVault(t, dir)
	runs, err := st2.ListExecRuns(ctx, 10)
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want the one recorded under v6", len(runs))
	}
	if runs[0].Meta.Command != "make dev" {
		t.Errorf("command = %q, want make dev", runs[0].Meta.Command)
	}
	if runs[0].Meta.CallerAgentComm != "" {
		t.Errorf("a v6 run gained an agent name from nowhere: %q", runs[0].Meta.CallerAgentComm)
	}

	// Applying it again is a no-op, not a permanent failure.
	if err := migrateV6toV7(ctx, st2.db); err != nil {
		t.Fatalf("second application: %v", err)
	}
}

// A run that received a value an agent invented and one the owner provisioned
// are different runs. The record has to say which, because the launch warning
// has scrolled away by the time anyone audits.
func TestExecRun_RemembersWhichValuesWereUnattended(t *testing.T) {
	st, scope := execRunFixture(t)
	ctx := context.Background()
	for _, n := range []string{"OWNED", "INVENTED"} {
		if err := st.PutEnvVar(ctx, scope, n, []byte("v-"+n), PutOpt{}); err != nil {
			t.Fatalf("put %s: %v", n, err)
		}
	}
	meta := ExecRunMeta{
		BynPath: "/p/.byn", Command: "make dev",
		Unattended: []string{"INVENTED"},
	}
	if _, err := st.RecordExecRun(ctx, scope, meta, []string{"OWNED", "INVENTED"}); err != nil {
		t.Fatalf("record: %v", err)
	}

	runs, err := st.ListExecRuns(ctx, 5)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	got := runs[0].Meta.Unattended
	if len(got) != 1 || got[0] != "INVENTED" {
		t.Errorf("unattended = %v, want [INVENTED]", got)
	}

	// A run with none says none, rather than an empty list that reads as
	// "byn checked and found nothing" versus "byn did not record this".
	if _, err := st.RecordExecRun(ctx, scope, ExecRunMeta{
		BynPath: "/p/.byn", Command: "make test",
	}, []string{"OWNED"}); err != nil {
		t.Fatalf("record second: %v", err)
	}
	runs, err = st.ListExecRuns(ctx, 5)
	if err != nil {
		t.Fatalf("list again: %v", err)
	}
	if len(runs[0].Meta.Unattended) != 0 {
		t.Errorf("a run with no unattended values reported %v", runs[0].Meta.Unattended)
	}
}
