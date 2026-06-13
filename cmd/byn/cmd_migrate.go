// `byn migrate` — adopt a byn vault tree into the daemon's system data root.
//
// Two modes (spec §6.2):
//
//	byn migrate                 relocate the legacy ~/.byn into the system path
//	                            (same machine: MOVE, keep trust + passkeys)
//	byn migrate --from <path>   import an EXTERNAL vault (copy; never delete the
//	                            source; DROP trust + passkeys — D1)
//
// Both are root-required (they write the _byn-owned system path and chown the
// adopted tree to the _byn service account). The heavy lifting — verify, atomic
// adopt, fail-safe — lives in internal/migrate; this file is a thin wrapper that
// does the root check, resolves the dirs + the _byn uid/gid, routes, and prints.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sandeepbaynes/byn/internal/migrate"
	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
)

// migrateDeps are the injectable seams `byn migrate` depends on, so the routing
// + root-handling + messaging can be unit-tested without root and without
// touching the real /var/lib. Production wiring is in defaultMigrateDeps.
type migrateDeps struct {
	euid       func() int                       // os.Geteuid
	systemDir  func() string                    // paths.SystemDataDir
	legacyDir  func() (string, error)           // paths.LegacyDataDir
	daemonUser func() (uid, gid int, err error) // privsep.LookupDaemonUser
	relocate   func(legacy, system string, o migrate.Options) error
	importFrom func(srcDir, system string, o migrate.Options) error
}

func defaultMigrateDeps() migrateDeps {
	return migrateDeps{
		euid:       os.Geteuid,
		systemDir:  paths.SystemDataDir,
		legacyDir:  paths.LegacyDataDir,
		daemonUser: privsep.LookupDaemonUser,
		relocate:   migrate.Relocate,
		importFrom: func(srcDir, system string, o migrate.Options) error {
			return migrate.Import(migrate.NewLocalSource(srcDir), system, o)
		},
	}
}

// runMigrate is the entry point wired into main's command switch.
func runMigrate(args []string) int {
	return runMigrateWith(args, defaultMigrateDeps(), os.Stdout, os.Stderr)
}

// runMigrateWith is the testable core: it parses flags, enforces root, resolves
// paths + the _byn uid/gid, routes to relocate vs import, and prints. All
// side-effecting dependencies arrive via deps so a test injects fakes.
func runMigrateWith(args []string, deps migrateDeps, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "import an external vault from this directory (default: relocate legacy ~/.byn)")
	force := fs.Bool("force", false, "replace a non-empty destination (refused otherwise)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s byn migrate takes no positional arguments (use --from <path> to import)\n", boldRed("Error:"))
		return exitErr
	}

	// Root required: migrate writes the _byn-owned system path and chowns the
	// adopted tree. Mirror `byn setup`'s root check + recovery hint.
	if deps.euid() != 0 {
		_, _ = fmt.Fprintln(stderr, boldRed("Error:")+" byn migrate must run as root (it writes the system data path and chowns it to "+privsep.DaemonUser+")")
		_, _ = fmt.Fprintln(stderr, yellow("Run:")+"   "+cyan("sudo byn migrate"))
		return exitErr
	}

	// Resolve the _byn service account that must own the adopted tree. Migrate
	// adopts with the correct ownership; it does NOT create the user — a missing
	// _byn means `byn setup` has not run yet.
	uid, gid, err := deps.daemonUser()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s %s service account not found — run %s first to provision it\n",
			boldRed("Error:"), privsep.DaemonUser, cyan("byn setup"))
		return exitErr
	}

	systemDir := deps.systemDir()
	opts := migrate.Options{UID: uid, GID: gid, Force: *force}

	if *from == "" {
		return runMigrateRelocate(deps, systemDir, opts, stdout, stderr)
	}
	return runMigrateImport(deps, *from, systemDir, opts, stdout, stderr)
}

// runMigrateRelocate handles `byn migrate` with no --from: move the legacy ~/.byn into
// the system path, keeping trust + passkeys (same machine).
func runMigrateRelocate(deps migrateDeps, systemDir string, opts migrate.Options, stdout, stderr io.Writer) int {
	legacy, err := deps.legacyDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s could not locate the legacy data dir: %v\n", boldRed("Error:"), err)
		return exitErr
	}
	if err := deps.relocate(legacy, systemDir, opts); err != nil {
		return reportMigrateErr(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "relocated %s -> %s (trust + passkeys preserved; old dir removed)\n", legacy, systemDir)
	return exitOK
}

// runMigrateImport handles `byn migrate --from <path>`: copy an external vault
// in, dropping trust + passkeys, and print the explicit re-trust notice.
func runMigrateImport(deps migrateDeps, fromDir, systemDir string, opts migrate.Options, stdout, stderr io.Writer) int {
	if err := deps.importFrom(fromDir, systemDir, opts); err != nil {
		return reportMigrateErr(stderr, err)
	}
	_, _ = fmt.Fprintf(stdout, "imported %s -> %s (source left untouched)\n", fromDir, systemDir)
	_, _ = fmt.Fprintln(stdout, "")
	_, _ = fmt.Fprintln(stdout, bold("Adopted DATA only.")+" Trust grants and passkey enrollments are NOT carried across an import.")
	_, _ = fmt.Fprintln(stdout, "Re-trust your "+cyan(".byn")+" files ("+cyan("byn trust")+") and re-enroll passkeys on this machine.")
	return exitOK
}

// reportMigrateErr prints a migrate error and returns the CLI error code. The
// internal/migrate errors are already actionable (they name the destination and
// suggest --force where relevant), so we surface them verbatim.
func reportMigrateErr(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "%s %v\n", boldRed("Error:"), err)
	return exitErr
}
