package setup

import (
	"errors"
	"strings"
	"testing"
)

// recorder captures the orchestration call sequence so the ordering +
// idempotency assertions can inspect exactly what Provision/Teardown did, in
// what order, with what arguments — all WITHOUT root.
type recorder struct {
	calls []string

	// fakeable knobs
	sudoUID          int
	sudoOK           bool
	legacyDir        string
	legacyExists     bool
	legacyErr        error
	daemonUID        int
	daemonGID        int
	daemonErr        error
	installHelperEr  error
	installSvcErr    error
	relocateErr      error
	writeOwnerErr    error
	verifyErr        error
	grantHomeErr     error

	// recorded values
	relocateUID, relocateGID int
	wroteOwnerUID            int
	wroteOwnerPath           string
	grantedHomeDir           string
}

const (
	testSystemDir   = "/test/system/byn"
	testOwnerRecord = "/test/system/byn/owner"
)

func (r *recorder) deps() Deps {
	return Deps{
		SudoUID: func() (int, bool) { r.calls = append(r.calls, "SudoUID"); return r.sudoUID, r.sudoOK },
		LegacyDir: func() (string, bool, error) {
			r.calls = append(r.calls, "LegacyDir")
			return r.legacyDir, r.legacyExists, r.legacyErr
		},
		SystemDataDir:   func() string { return testSystemDir },
		OwnerRecordPath: func() string { return testOwnerRecord },
		DaemonUser: func() (int, int, error) {
			r.calls = append(r.calls, "DaemonUser")
			return r.daemonUID, r.daemonGID, r.daemonErr
		},
		InstallSpawnHelper: func() error { r.calls = append(r.calls, "InstallSpawnHelper"); return r.installHelperEr },
		InstallService:     func() error { r.calls = append(r.calls, "InstallService"); return r.installSvcErr },
		Relocate: func(legacy, sys string, uid, gid int) error {
			r.calls = append(r.calls, "Relocate")
			r.relocateUID, r.relocateGID = uid, gid
			return r.relocateErr
		},
		GrantHomeAccess: func(homeDir string) error {
			r.calls = append(r.calls, "GrantHomeAccess")
			r.grantedHomeDir = homeDir
			return r.grantHomeErr
		},
		WriteOwnerRecord: func(path string, uid int) error {
			r.calls = append(r.calls, "WriteOwnerRecord")
			r.wroteOwnerPath, r.wroteOwnerUID = path, uid
			return r.writeOwnerErr
		},
		Verify: func(sysDir, ownerPath string, ownerUID, dUID, dGID int) error {
			r.calls = append(r.calls, "Verify")
			return r.verifyErr
		},
	}
}

func happyRecorder() *recorder {
	return &recorder{
		sudoUID: 501, sudoOK: true,
		daemonUID: 200, daemonGID: 200,
		// legacyDir is set even on a fresh install (no vault) because SUDO_USER
		// is always set when `sudo byn setup` runs — LegacyDir returns the path
		// regardless of whether the directory exists.
		legacyDir: "/home/testuser/.byn",
	}
}

func TestProvision_HappyPath_FreshInstall_NoMigrate(t *testing.T) {
	r := happyRecorder() // legacyExists = false
	res, err := Provision(r.deps())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// Fresh install: no Relocate. GrantHomeAccess runs between LegacyDir and
	// WriteOwnerRecord; the service is installed/started LAST.
	want := []string{"SudoUID", "InstallSpawnHelper", "DaemonUser", "LegacyDir", "GrantHomeAccess", "WriteOwnerRecord", "InstallService", "Verify"}
	assertSeq(t, r.calls, want)
	if res.Migrated {
		t.Error("Migrated = true on a fresh install (no legacy dir)")
	}
	if res.OwnerUID != 501 {
		t.Errorf("OwnerUID = %d, want 501", res.OwnerUID)
	}
	if r.wroteOwnerUID != 501 {
		t.Errorf("recorded owner UID = %d, want 501", r.wroteOwnerUID)
	}
	if r.wroteOwnerPath != testOwnerRecord {
		t.Errorf("owner record path = %q, want %q", r.wroteOwnerPath, testOwnerRecord)
	}
	if r.grantedHomeDir != "/home/testuser" {
		t.Errorf("GrantHomeAccess called with %q, want /home/testuser", r.grantedHomeDir)
	}
	if res.HomeACLWarning != "" {
		t.Errorf("unexpected HomeACLWarning = %q", res.HomeACLWarning)
	}
}

func TestProvision_HappyPath_LegacyPresent_CallsRelocate(t *testing.T) {
	r := happyRecorder()
	r.legacyExists = true
	r.legacyDir = "/home/alice/.byn"
	res, err := Provision(r.deps())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	// GrantHomeAccess runs between LegacyDir and Relocate; service is installed LAST.
	want := []string{"SudoUID", "InstallSpawnHelper", "DaemonUser", "LegacyDir", "GrantHomeAccess", "Relocate", "WriteOwnerRecord", "InstallService", "Verify"}
	assertSeq(t, r.calls, want)
	if !res.Migrated {
		t.Error("Migrated = false despite a present legacy dir")
	}
	if res.LegacyDir != "/home/alice/.byn" {
		t.Errorf("LegacyDir = %q, want /home/alice/.byn", res.LegacyDir)
	}
	// Relocate must chown to the _byn account (DaemonUser), not the owner.
	if r.relocateUID != 200 || r.relocateGID != 200 {
		t.Errorf("Relocate chown = %d:%d, want 200:200 (_byn)", r.relocateUID, r.relocateGID)
	}
}

func TestProvision_NoSudoContext_ErrorsBeforeAnySideEffect(t *testing.T) {
	r := happyRecorder()
	r.sudoOK = false // SUDO_UID unset / run as real root
	_, err := Provision(r.deps())
	if err == nil {
		t.Fatal("expected an error when SUDO_UID is missing")
	}
	if !errors.Is(err, errNoSudoContext) {
		t.Errorf("error = %v, want errNoSudoContext", err)
	}
	// No owner record of 0, no side effects at all beyond the SudoUID probe.
	assertSeq(t, r.calls, []string{"SudoUID"})
	if r.wroteOwnerUID != 0 {
		t.Errorf("wrote owner UID %d despite no sudo context — must never record 0", r.wroteOwnerUID)
	}
}

func TestProvision_SudoUIDZero_Refused(t *testing.T) {
	r := happyRecorder()
	r.sudoOK = true
	r.sudoUID = 0 // ok=true but uid 0 — still refused (defense in depth)
	_, err := Provision(r.deps())
	if !errors.Is(err, errNoSudoContext) {
		t.Fatalf("error = %v, want errNoSudoContext for uid 0", err)
	}
}

func TestProvision_GrantHomeAccess_Failure_IsNonFatal(t *testing.T) {
	r := happyRecorder()
	r.grantHomeErr = errors.New("setfacl: not found")
	res, err := Provision(r.deps())
	if err != nil {
		t.Fatalf("Provision must not abort on GrantHomeAccess failure, got: %v", err)
	}
	if res.HomeACLWarning == "" {
		t.Error("HomeACLWarning must be set when GrantHomeAccess fails")
	}
	if !strings.Contains(res.HomeACLWarning, "setfacl: not found") {
		t.Errorf("HomeACLWarning does not include the underlying error: %q", res.HomeACLWarning)
	}
	// Provision must continue through the full sequence despite the failure.
	want := []string{"SudoUID", "InstallSpawnHelper", "DaemonUser", "LegacyDir", "GrantHomeAccess", "WriteOwnerRecord", "InstallService", "Verify"}
	assertSeq(t, r.calls, want)
}

func TestProvision_GrantHomeAccess_Skipped_WhenNoLegacyDir(t *testing.T) {
	// When LegacyDir returns "" (no SUDO_USER / can't determine home), GrantHomeAccess
	// must not be called — there is no home path to grant.
	r := happyRecorder()
	r.legacyDir = "" // override: pretend SUDO_USER was unset (unusual but tested)
	_, err := Provision(r.deps())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, c := range r.calls {
		if c == "GrantHomeAccess" {
			t.Error("GrantHomeAccess must not be called when legacyDir is empty")
		}
	}
}

func TestProvision_Idempotent_ReRunIsCleanNoOp(t *testing.T) {
	// Idempotency at the orchestration layer: each injected primitive tolerates
	// "already done" (returns nil), so a second Provision drives the identical
	// successful sequence. This mirrors a re-run on an already-provisioned host.
	r := happyRecorder()
	if _, err := Provision(r.deps()); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	first := append([]string(nil), r.calls...)

	r2 := happyRecorder()
	if _, err := Provision(r2.deps()); err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	assertSeq(t, r2.calls, first)
}

func TestProvision_StopsOnEachStepError(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*recorder)
		lastFn  string // the call that fails (last in the sequence)
		wantMsg string
	}{
		{"InstallSpawnHelper", func(r *recorder) { r.installHelperEr = errors.New("boom") }, "InstallSpawnHelper", "spawn helper"},
		{"DaemonUser", func(r *recorder) { r.daemonErr = errors.New("boom") }, "DaemonUser", "service account"},
		{"InstallService", func(r *recorder) { r.installSvcErr = errors.New("boom") }, "InstallService", "system service"},
		{"LegacyDir", func(r *recorder) { r.legacyErr = errors.New("boom") }, "LegacyDir", "legacy data dir"},
		{"Relocate", func(r *recorder) { r.legacyExists = true; r.legacyDir = "/h/.byn"; r.relocateErr = errors.New("boom") }, "Relocate", "relocate"},
		{"WriteOwnerRecord", func(r *recorder) { r.writeOwnerErr = errors.New("boom") }, "WriteOwnerRecord", "owner UID"},
		{"Verify", func(r *recorder) { r.verifyErr = errors.New("boom") }, "Verify", "verify"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := happyRecorder()
			tc.mutate(r)
			_, err := Provision(r.deps())
			if err == nil {
				t.Fatalf("expected an error when %s fails", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantMsg)
			}
			// The failing call must be the LAST one recorded — Provision stops.
			if len(r.calls) == 0 || r.calls[len(r.calls)-1] != tc.lastFn {
				t.Errorf("last call = %v, want it to stop at %q", r.calls, tc.lastFn)
			}
		})
	}
}

func assertSeq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("call sequence = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call sequence = %v, want %v (differ at %d)", got, want, i)
		}
	}
}
