package setup

import (
	"errors"
	"strings"
	"testing"
)

type teardownRecorder struct {
	calls []string

	uninstallSvcErr error
	removeHelperErr error
	removeOwnerErr  error
	purgeErr        error

	purgedDir string
}

func (r *teardownRecorder) deps() TeardownDeps {
	return TeardownDeps{
		UninstallService:  func() error { r.calls = append(r.calls, "UninstallService"); return r.uninstallSvcErr },
		RemoveSpawnHelper: func() error { r.calls = append(r.calls, "RemoveSpawnHelper"); return r.removeHelperErr },
		RemoveOwnerRecord: func() error { r.calls = append(r.calls, "RemoveOwnerRecord"); return r.removeOwnerErr },
		SystemDataDir:     func() string { return testSystemDir },
		PurgeDataDir: func(dir string) error {
			r.calls = append(r.calls, "PurgeDataDir")
			r.purgedDir = dir
			return r.purgeErr
		},
	}
}

func TestTeardown_NoPurge_LeavesVault(t *testing.T) {
	r := &teardownRecorder{}
	res, err := Teardown(r.deps(), false)
	if err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	// Without purge: NEVER call PurgeDataDir — the vault is untouched.
	want := []string{"UninstallService", "RemoveSpawnHelper", "RemoveOwnerRecord"}
	assertSeq(t, r.calls, want)
	if res.Purged {
		t.Error("Purged = true without --purge — the vault must be left intact")
	}
	if r.purgedDir != "" {
		t.Errorf("PurgeDataDir was called (dir %q) without --purge", r.purgedDir)
	}
}

func TestTeardown_Purge_RemovesVault(t *testing.T) {
	r := &teardownRecorder{}
	res, err := Teardown(r.deps(), true)
	if err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	want := []string{"UninstallService", "RemoveSpawnHelper", "RemoveOwnerRecord", "PurgeDataDir"}
	assertSeq(t, r.calls, want)
	if !res.Purged {
		t.Error("Purged = false despite --purge")
	}
	if r.purgedDir != testSystemDir {
		t.Errorf("purged %q, want %q", r.purgedDir, testSystemDir)
	}
}

func TestTeardown_StopsOnError(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*teardownRecorder)
		purge   bool
		lastFn  string
		wantMsg string
	}{
		{"UninstallService", func(r *teardownRecorder) { r.uninstallSvcErr = errors.New("x") }, false, "UninstallService", "system service"},
		{"RemoveSpawnHelper", func(r *teardownRecorder) { r.removeHelperErr = errors.New("x") }, false, "RemoveSpawnHelper", "spawn helper"},
		{"RemoveOwnerRecord", func(r *teardownRecorder) { r.removeOwnerErr = errors.New("x") }, false, "RemoveOwnerRecord", "owner record"},
		{"PurgeDataDir", func(r *teardownRecorder) { r.purgeErr = errors.New("x") }, true, "PurgeDataDir", "purge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &teardownRecorder{}
			tc.mutate(r)
			_, err := Teardown(r.deps(), tc.purge)
			if err == nil {
				t.Fatalf("expected an error when %s fails", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantMsg)
			}
			if r.calls[len(r.calls)-1] != tc.lastFn {
				t.Errorf("last call = %v, want it to stop at %q", r.calls, tc.lastFn)
			}
		})
	}
}
