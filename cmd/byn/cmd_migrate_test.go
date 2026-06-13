package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/migrate"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// fakeMigrateDeps returns a migrateDeps with harmless defaults (root, a
// provisioned _byn, fixed dirs) and recording relocate/import stubs. Tests
// override individual fields.
func fakeMigrateDeps() (migrateDeps, *migrateCalls) {
	calls := &migrateCalls{}
	deps := migrateDeps{
		euid:       func() int { return 0 }, // root by default
		systemDir:  func() string { return "/sys/byn" },
		legacyDir:  func() (string, error) { return "/home/u/.byn", nil },
		daemonUser: func() (int, int, error) { return 410, 410, nil },
		relocate: func(legacy, system string, o migrate.Options) error {
			calls.relocate++
			calls.relocLegacy, calls.relocSystem, calls.relocOpts = legacy, system, o
			return calls.relocErr
		},
		importFrom: func(srcDir, system string, o migrate.Options) error {
			calls.imports++
			calls.importSrc, calls.importSystem, calls.importOpts = srcDir, system, o
			return calls.importErr
		},
	}
	return deps, calls
}

type migrateCalls struct {
	relocate                 int
	relocLegacy, relocSystem string
	relocOpts                migrate.Options
	relocErr                 error
	imports                  int
	importSrc, importSystem  string
	importOpts               migrate.Options
	importErr                error
}

func runMigrateCaptured(args []string, deps migrateDeps) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = runMigrateWith(args, deps, &out, &errb)
	return code, out.String(), errb.String()
}

func TestMigrate_NoFromRoutesToRelocate(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	code, stdout, _ := runMigrateCaptured(nil, deps)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if calls.relocate != 1 || calls.imports != 0 {
		t.Fatalf("routing wrong: relocate=%d import=%d", calls.relocate, calls.imports)
	}
	if calls.relocLegacy != "/home/u/.byn" || calls.relocSystem != "/sys/byn" {
		t.Fatalf("relocate got legacy=%q system=%q", calls.relocLegacy, calls.relocSystem)
	}
	if calls.relocOpts.UID != 410 || calls.relocOpts.GID != 410 {
		t.Fatalf("relocate uid/gid not threaded: %+v", calls.relocOpts)
	}
	if !strings.Contains(stdout, "relocated") || !strings.Contains(stdout, "preserved") {
		t.Fatalf("relocate stdout missing keep-notice: %q", stdout)
	}
}

func TestMigrate_FromRoutesToImportWithReTrustNotice(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	code, stdout, _ := runMigrateCaptured([]string{"--from", "/mnt/backup/.byn"}, deps)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if calls.imports != 1 || calls.relocate != 0 {
		t.Fatalf("routing wrong: relocate=%d import=%d", calls.relocate, calls.imports)
	}
	if calls.importSrc != "/mnt/backup/.byn" || calls.importSystem != "/sys/byn" {
		t.Fatalf("import got src=%q system=%q", calls.importSrc, calls.importSystem)
	}
	// The explicit re-trust + re-enroll notice (D1) must be printed.
	for _, want := range []string{"DATA only", "NOT carried", "Re-trust", "re-enroll passkeys"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("import stdout missing %q; got:\n%s", want, stdout)
		}
	}
}

func TestMigrate_ForceThreadsThrough(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	if code, _, _ := runMigrateCaptured([]string{"--force"}, deps); code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !calls.relocOpts.Force {
		t.Fatal("--force did not reach migrate.Options")
	}

	deps2, calls2 := fakeMigrateDeps()
	if code, _, _ := runMigrateCaptured([]string{"--from", "/x", "--force"}, deps2); code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if !calls2.importOpts.Force {
		t.Fatal("--force did not reach import migrate.Options")
	}
}

func TestMigrate_NonRootRefused(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	deps.euid = func() int { return 501 }
	code, _, stderr := runMigrateCaptured(nil, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if calls.relocate != 0 || calls.imports != 0 {
		t.Fatal("non-root must not invoke migrate")
	}
	if !strings.Contains(stderr, "root") || !strings.Contains(stderr, "sudo byn migrate") {
		t.Fatalf("non-root error not actionable: %q", stderr)
	}
}

func TestMigrate_MissingDaemonUserTellsToRunSetup(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	deps.daemonUser = func() (int, int, error) { return 0, 0, privsep.ErrNotProvisioned }
	code, _, stderr := runMigrateCaptured(nil, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if calls.relocate != 0 {
		t.Fatal("missing _byn must not invoke relocate")
	}
	if !strings.Contains(stderr, "byn setup") || !strings.Contains(stderr, privsep.DaemonUser) {
		t.Fatalf("missing-user error not actionable: %q", stderr)
	}
}

func TestMigrate_PositionalArgsRejected(t *testing.T) {
	deps, _ := fakeMigrateDeps()
	code, _, stderr := runMigrateCaptured([]string{"somepath"}, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if !strings.Contains(stderr, "no positional") {
		t.Fatalf("positional-arg error unclear: %q", stderr)
	}
}

func TestMigrate_RelocateErrorSurfaced(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	calls.relocErr = errors.New("destination is not empty — pass --force")
	code, _, stderr := runMigrateCaptured(nil, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if !strings.Contains(stderr, "--force") {
		t.Fatalf("relocate error not surfaced: %q", stderr)
	}
}

func TestMigrate_ImportErrorSurfaced(t *testing.T) {
	deps, calls := fakeMigrateDeps()
	calls.importErr = errors.New("verify vault \"default\": bad db")
	code, _, stderr := runMigrateCaptured([]string{"--from", "/x"}, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if !strings.Contains(stderr, "verify vault") {
		t.Fatalf("import error not surfaced: %q", stderr)
	}
}

func TestMigrate_LegacyDirErrorSurfaced(t *testing.T) {
	deps, _ := fakeMigrateDeps()
	deps.legacyDir = func() (string, error) { return "", errors.New("no home dir") }
	code, _, stderr := runMigrateCaptured(nil, deps)
	if code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
	if !strings.Contains(stderr, "legacy data dir") {
		t.Fatalf("legacy-dir error not surfaced: %q", stderr)
	}
}

func TestMigrate_BadFlagRejected(t *testing.T) {
	deps, _ := fakeMigrateDeps()
	if code, _, _ := runMigrateCaptured([]string{"--nope"}, deps); code != exitErr {
		t.Fatalf("exit = %d, want %d", code, exitErr)
	}
}
