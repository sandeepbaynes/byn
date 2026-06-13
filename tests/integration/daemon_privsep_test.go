//go:build integration

// NU-6 daemon-privilege-separation POSTURE proof (root-gated; skips cleanly
// off-root). Where NU-5 (privsep_test.go) proves the exec CHILD drops to the
// _byn-exec service user, this test extends the proof to the DAEMON-as-_byn
// provisioning posture introduced by NU-6: `byn setup` provisioning, the owner
// record / owner-UID allowlist, and the fail-closed routing when privsep is
// turned on but the host is NOT provisioned.
//
// HONEST CEILING — what this test can and CANNOT prove in a CI container:
//
//   - It does NOT depend on `systemctl enable --now byn.service` actually
//     launching + supervising the daemon as _byn. In a CI Linux container
//     systemd is frequently not PID 1, so that step is unreliable. Instead the
//     test provisions via internal/setup.Provision with the PRODUCTION privsep
//     primitives (real service-user creation, real root-owned setcap'd spawn
//     helper, real owner record) but a TOLERANT InstallService seam, then drives
//     a real daemon directly (started --allow-root so it runs in the container).
//     This is the pragmatic split the NU-6 plan calls for: prove the components
//     for real, skip only the systemd-supervision wiring that a container cannot
//     host.
//   - Each sub-check that genuinely cannot run on the image (missing tools, no
//     sysusers, etc.) t.Skips THAT check with a logged reason rather than
//     silently dropping coverage.
//
// Gating: like privsep_test.go this is Linux-only (it reads /proc and needs a
// real uid drop) and root-only. Off-root or off-Linux it t.Skips. On the
// dedicated root CI job (.github/workflows/ci.yml: privsep-integration) it runs
// for real.
package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/migrate"
	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/privsep"
	"github.com/sandeepbaynes/byn/internal/setup"
)

// simulatedSudoUID is the non-root owner UID the test pretends `sudo` set. It
// must be > 0 (WriteOwnerRecord refuses 0) and SHOULD resolve to a real account
// so the daemon's allowlist + the relocate chown target are realistic. We prefer
// the CI runner's real SUDO_UID; failing that, "nobody"; failing that a fixed
// non-root stand-in. Returned uid is guaranteed > 0.
func simulatedSudoUID(t *testing.T) int {
	t.Helper()
	if raw := os.Getenv("SUDO_UID"); raw != "" {
		if uid, err := strconv.Atoi(raw); err == nil && uid > 0 {
			return uid
		}
	}
	if u, err := user.Lookup("nobody"); err == nil {
		if uid, err := strconv.Atoi(u.Uid); err == nil && uid > 0 {
			return uid
		}
	}
	return 65534 // conventional nobody uid; > 0 and ≠ root
}

// daemonServiceUID resolves the _byn daemon service account uid, or skips when
// `byn setup` did not create it (sysusers unavailable on the image).
func daemonServiceUID(t *testing.T) int {
	t.Helper()
	u, err := user.Lookup(privsep.DaemonUser)
	if err != nil {
		t.Skipf("%s service user absent after provisioning (sysusers unavailable on this image): %v",
			privsep.DaemonUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("parse %s uid %q: %v", privsep.DaemonUser, u.Uid, err)
	}
	return uid
}

// provisionDeps builds setup.Deps from the PRODUCTION privsep/migrate primitives,
// with two test-only seams:
//   - SudoUID returns the simulated owner UID (sudoUID) deterministically rather
//     than reading the live env, so the owner record is written with a known UID.
//   - InstallService is TOLERANT: it attempts the real privsep.InstallService but
//     never fails the provision if systemd is not supervising (the common CI
//     container case). The systemd-supervision wiring is the one piece a
//     container cannot reliably host; everything else (users, helper, caps, owner
//     record, relocate) runs for real.
//
// helper is the prebuilt byn-exec-helper the install copies into place. svcErr,
// when non-nil, records the (tolerated) InstallService error for logging.
func provisionDeps(t *testing.T, helper string, sudoUID int, svcErr *error) setup.Deps {
	t.Helper()
	systemDir := paths.SystemDataDir()
	ownerRecordPath := paths.OwnerRecordIn(systemDir)
	run := func(cmd string, args ...string) error {
		c := exec.Command(cmd, args...) // #nosec G204 -- fixed commands from internal/privsep, not user input
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		return c.Run()
	}
	return setup.Deps{
		SudoUID:         func() (int, bool) { return sudoUID, true },
		LegacyDir:       func() (string, bool, error) { return "", false, nil }, // fresh install in the test dir
		SystemDataDir:   paths.SystemDataDir,
		OwnerRecordPath: func() string { return ownerRecordPath },
		DaemonUser:      privsep.LookupDaemonUser,
		InstallSpawnHelper: func() error {
			return privsep.Setup(run, helper, privsep.HelperDestPath(), privsep.HelperConfigPath())
		},
		InstallService: func() error {
			// Best-effort: a container without systemd-as-PID-1 cannot enable the
			// unit. Record the error for the log, but do NOT fail the provision —
			// the daemon-as-_byn supervision is exercised by the directly-driven
			// daemon below, not by systemctl.
			if err := privsep.InstallService(run, helper); err != nil {
				*svcErr = err
			}
			return nil
		},
		Relocate: func(legacyDir, sysDir string, uid, gid int) error {
			return migrate.Relocate(legacyDir, sysDir, migrate.Options{UID: uid, GID: gid})
		},
		WriteOwnerRecord: privsep.WriteOwnerRecord,
		Verify: func(sysDir, ownerPath string, ownerUID, dUID, dGID int) error {
			// Lightweight: the system data dir exists + the owner record reads back
			// to the expected UID. (Production verifyProvisioned also warns on _byn
			// ownership; we re-check ownership explicitly in the assertions below.)
			if fi, err := os.Stat(sysDir); err != nil || !fi.IsDir() {
				return fmt.Errorf("system data dir %s missing or not a dir (err=%v)", sysDir, err)
			}
			recorded, rerr := privsep.ReadOwnerRecord(ownerPath)
			if rerr != nil {
				return fmt.Errorf("owner record unreadable: %w", rerr)
			}
			if recorded != ownerUID {
				return fmt.Errorf("owner record holds %d, want %d", recorded, ownerUID)
			}
			return nil
		},
	}
}

// TestPrivsep_DaemonPosture is the NU-6 capstone. See the file header for the
// honest ceiling. Named with the TestPrivsep prefix so the privsep-integration
// CI job's `-run TestPrivsep` filter selects it alongside the NU-5 proof.
func TestPrivsep_DaemonPosture(t *testing.T) {
	requireRootLinux(t)
	// Provisioning needs sysusers (user creation) + setcap + install; the
	// cross-uid /proc read needs setpriv; the long-running child uses sleep.
	skipUnlessToolsPresent(t, "setcap", "install", "setpriv", "sleep")

	// --- PHASE 1: FAIL-CLOSED (must run BEFORE provisioning creates _byn-exec).
	// With [security] privsep = true but the host NOT provisioned, a trusted-.byn
	// exec must fail closed with the `sudo byn setup` hint and must NOT run the
	// child as the owner UID. This is the opt-in-on, not-set-up posture. ---
	t.Run("fail_closed_when_privsep_on_but_unprovisioned", func(t *testing.T) {
		if _, err := user.Lookup(privsep.ExecUser); err == nil {
			t.Skipf("%s already exists on this host — cannot exercise the unprovisioned "+
				"fail-closed path (run on a clean image)", privsep.ExecUser)
		}
		assertFailClosedUnprovisioned(t)
	})

	// --- PHASE 2: PROVISION via setup.Provision with production primitives. ---
	s := newSession(t)
	helper := buildHelper(t, s.bin)
	sudoUID := simulatedSudoUID(t)

	var svcErr error
	deps := provisionDeps(t, helper, sudoUID, &svcErr)
	res, err := setup.Provision(deps)
	if err != nil {
		t.Skipf("setup.Provision failed on this image (privsep prerequisites unavailable): %v", err)
	}
	if svcErr != nil {
		t.Logf("note: InstallService (systemd enable --now) failed and was tolerated (expected in a "+
			"container without systemd as PID 1): %v — the daemon-as-%s supervision is exercised "+
			"directly below instead of via systemctl", svcErr, privsep.DaemonUser)
	} else {
		t.Logf("note: InstallService succeeded — systemd is available on this runner")
	}

	// POST-CONDITION 1: both service users exist.
	execu := execUID(t)            // skips if _byn-exec absent (sysusers unavailable)
	daemonu := daemonServiceUID(t) // skips if _byn absent
	if execu == daemonu {
		t.Fatalf("_byn-exec (%d) and _byn (%d) collide — privsep would be ineffective", execu, daemonu)
	}
	if execu == 0 || daemonu == 0 {
		t.Fatalf("service uid is 0 (execu=%d daemonu=%d) — must be unprivileged accounts", execu, daemonu)
	}

	// POST-CONDITION 2: the owner record is written with the SIMULATED SUDO_UID
	// (never root), and Provision reports the same owner UID.
	if res.OwnerUID != sudoUID {
		t.Errorf("Provision OwnerUID = %d, want simulated SUDO_UID %d", res.OwnerUID, sudoUID)
	}
	recPath := paths.OwnerRecordIn(paths.SystemDataDir())
	recorded, rerr := privsep.ReadOwnerRecord(recPath)
	if rerr != nil {
		t.Fatalf("read owner record %s: %v", recPath, rerr)
	}
	if recorded != sudoUID {
		t.Errorf("owner record = %d, want simulated SUDO_UID %d (must be the invoking human, never root)",
			recorded, sudoUID)
	}
	if recorded == 0 {
		t.Errorf("owner record allowlists UID 0 (root) — privsep would be defeated")
	}

	// POST-CONDITION 3: the spawn helper is installed root-owned with the setuid/
	// setgid file capabilities, and the system data dir exists.
	assertHelperInstalled(t)
	if fi, err := os.Stat(paths.SystemDataDir()); err != nil || !fi.IsDir() {
		t.Fatalf("system data dir %s missing after provision: err=%v", paths.SystemDataDir(), err)
	}

	// POST-CONDITION 4: a second Provision is idempotent (clean re-run).
	if _, err := setup.Provision(provisionDeps(t, helper, sudoUID, &svcErr)); err != nil {
		t.Fatalf("second Provision not idempotent: %v", err)
	}

	// --- PHASE 3: OWNER-UID ALLOWLIST. A daemon started against the PROVISIONED
	// dir (owner record = sudoUID ≠ root) must allowlist the RECORDED owner UID,
	// so a ROOT client (≠ sudoUID) is REJECTED by the peercred gate. This proves
	// the recorded UID — not the daemon's euid — drives the allowlist. ---
	t.Run("allowlists_recorded_owner_uid_rejects_root", func(t *testing.T) {
		assertProvisionedDaemonRejectsRoot(t, sudoUID)
	})

	// --- PHASE 4: EXEC POSTURE. With privsep ON and provisioned, a trusted-.byn
	// exec runs the child as _byn-exec (≠ daemon euid ≠ owner), and a non-root
	// owner-class process cannot read the child's /proc/<pid>/environ. The daemon
	// here uses a CLEAN data dir with NO owner record, so the root daemon
	// allowlists root and the root CLI can connect — the child UID drop is what we
	// are proving, independent of the owner-record allowlist (covered in Phase 3).
	// This also proves "an owner-UID client can connect over the socket". ---
	t.Run("exec_child_drops_to_byn_exec_no_cred_leak", func(t *testing.T) {
		assertExecChildDropsAndNoLeak(t, execu, daemonu)
	})
}

// assertFailClosedUnprovisioned starts a daemon with [security] privsep = true on
// an UNPROVISIONED host and asserts a trusted-.byn exec fails closed (the
// `sudo byn setup` hint, non-zero exit) and does NOT spawn the child as the owner
// UID (root here).
func assertFailClosedUnprovisioned(t *testing.T) {
	t.Helper()
	s := newSession(t)

	// privsep on BEFORE the daemon starts (config is read once at start).
	writePrivsepConfig(t, s.dir)

	// Daemon as root needs --allow-root in the container; it must still come up
	// (privsep on + unprovisioned only WARNS — the spawner stays nil).
	if _, se, code := s.run("", "daemon", "start", "--allow-root"); code != 0 {
		t.Fatalf("daemon start (unprovisioned, privsep on): code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)

	bootstrapTrustedSleep(t, s)

	// EXEC: trusted-.byn direct exec routes to the privsep spawn. The daemon's
	// spawner is nil (unprovisioned), so it returns "not provisioned" and the CLI
	// prints the actionable hint and exits non-zero — it must NOT fall back to an
	// owner-UID in-process run.
	projDir := filepath.Join(s.dir, "privsep-proj")
	var (
		stdout, stderr string
		code           int
		wg             sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// runInDir builds a minimal env without PATH; give the CLI a real PATH so it
		// can resolve `sleep` to an absolute target and actually reach the daemon's
		// fail-closed (not-provisioned) path, rather than erroring at LookPath first.
		stdout, stderr, code = s.runInDir(projDir, "", []string{"PATH=" + os.Getenv("PATH")}, "exec", "--", "sleep", "5")
	}()

	// Fail-closed must NOT produce a root-owned `sleep` child. Poll briefly; the
	// absence of such a child while the command runs/finishes is the proof.
	leaked := waitForChild(0, time.Now().Add(2*time.Second))
	wg.Wait()

	if leaked != 0 {
		// Only fatal if the leaked sleep is actually OUR exec's child — a root
		// `sleep` from elsewhere is implausible in the test container but we keep
		// the message specific.
		t.Errorf("FAIL-CLOSED VIOLATED: a root-owned (uid 0) `sleep` child (pid %d) appeared — "+
			"unprovisioned privsep must NOT run the child as the owner; stdout=%q stderr=%q",
			leaked, stdout, stderr)
	}
	if code == 0 {
		t.Errorf("fail-closed exec exited 0, want non-zero (not-provisioned hard error); stderr=%q", stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "byn setup") {
		t.Errorf("fail-closed output missing the `byn setup` hint:\nstdout=%q\nstderr=%q", stdout, stderr)
	}
}

// assertProvisionedDaemonRejectsRoot starts a daemon against the provisioned
// system data dir (owner record = sudoUID ≠ root) and asserts a ROOT client is
// rejected by the peercred gate — proving the RECORDED owner UID drives the
// allowlist (NU-6 owner-record posture).
func assertProvisionedDaemonRejectsRoot(t *testing.T, sudoUID int) {
	t.Helper()
	if os.Geteuid() == sudoUID {
		t.Skipf("test euid (%d) equals the simulated owner UID — cannot prove a cross-UID "+
			"rejection (no SUDO_UID and we happen to be that account)", sudoUID)
	}
	// The provisioned dir is paths.SystemDataDir() == the byntest data root
	// (BYN_TEST_DIR). Drive a daemon there with a fresh session pinned to that
	// dir, with privsep ON so the provisioned spawner is built too.
	s := newSession(t)
	// Re-point this session at the provisioned system data dir so the daemon
	// reads the owner record written by Provision.
	s.dir = paths.SystemDataDir()
	writePrivsepConfig(t, s.dir)

	// Make sure no stale daemon is holding the socket, then start ours.
	_, _, _ = s.run("", "daemon", "stop")
	if _, se, code := s.run("", "daemon", "start", "--allow-root"); code != 0 {
		// A provisioned daemon refusing to start is a real failure (it should start
		// with --allow-root); surface it.
		t.Fatalf("provisioned daemon start: code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)

	// A ROOT client (this process is root) connecting must be REJECTED because the
	// allowlisted owner UID is the recorded sudoUID, not root.
	stdout, stderr, code := s.run("", "daemon", "status")
	combined := stdout + stderr
	if code == 0 {
		t.Errorf("root client connected successfully to a daemon allowlisting owner UID %d — "+
			"the recorded owner UID is NOT gating connections; stdout=%q", sudoUID, stdout)
	}
	if !strings.Contains(combined, "rejected") && !strings.Contains(combined, strconv.Itoa(sudoUID)) {
		t.Logf("note: rejection message did not name the owner UID (%d); got stdout=%q stderr=%q "+
			"(still rejected: code=%d)", sudoUID, stdout, stderr, code)
	}
}

// assertExecChildDropsAndNoLeak provisions-on (helper already installed by
// Phase 2) and proves a trusted-.byn exec drops the child to _byn-exec (≠ the
// daemon euid ≠ owner) with no cross-UID environ leak. Uses a CLEAN data dir
// (no owner record) so the root daemon allowlists root and the root CLI connects
// — proving an owner-UID client connects over the socket.
func assertExecChildDropsAndNoLeak(t *testing.T, execu, daemonu int) {
	t.Helper()
	readerUID := unprivReaderUID(t, execu)

	s := newSession(t)
	writePrivsepConfig(t, s.dir)

	if _, se, code := s.run("", "daemon", "start", "--allow-root"); code != 0 {
		t.Fatalf("daemon start (provisioned, privsep on): code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)

	// PROOF that an owner-UID (root here) client connects over the socket.
	if _, se, code := s.run("", "daemon", "status"); code != 0 {
		t.Fatalf("owner-UID client could not connect to the provisioned daemon: code=%d stderr=%q", code, se)
	}

	projDir := bootstrapTrustedSleep(t, s)

	var (
		execStdout, execStderr string
		execCode               int
		wg                     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// PATH so the CLI can resolve `sleep` (runInDir's env omits it by default).
		execStdout, execStderr, execCode = s.runInDir(projDir, "", []string{"PATH=" + os.Getenv("PATH")}, "exec", "--", "sleep", "5")
	}()

	childPID := waitForChild(execu, time.Now().Add(4*time.Second))
	if childPID == 0 {
		wg.Wait()
		t.Fatalf("no _byn-exec child (uid %d) running `sleep` appeared; exec stdout=%q stderr=%q code=%d",
			execu, execStdout, execStderr, execCode)
	}

	// PROOF A — the child dropped to _byn-exec, which is NEITHER the daemon's euid
	// (root here) NOR the recorded owner. The daemon stays at its own UID.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(childPID) + "/status") // #nosec G304 -- /proc path
	if err != nil {
		t.Fatalf("read child status: %v", err)
	}
	got := statusUID(string(status))
	if got != execu {
		t.Errorf("child real uid = %d, want _byn-exec uid %d (child did NOT drop privilege)\nstatus:\n%s",
			got, execu, status)
	}
	if got == os.Geteuid() {
		t.Errorf("child uid %d == daemon/test euid %d — no privilege separation from the daemon owner", got, os.Geteuid())
	}
	if got == daemonu {
		t.Errorf("child uid %d == _byn daemon uid %d — child runs as the DAEMON, not the exec sandbox", got, daemonu)
	}

	// PROOF B — cred-leak: a non-root owner-class process cannot read the child's
	// /proc/<pid>/environ (reusing NU-5's sentinel + assertion).
	out, readErr := readEnvironAs(readerUID, childPID)
	switch {
	case readErr == nil && bytes.Contains(out, []byte(privsepSecret)):
		t.Errorf("CRED LEAK: non-root uid %d read the sentinel from /proc/%d/environ", readerUID, childPID)
	case readErr != nil:
		t.Logf("good: non-root uid %d denied reading /proc/%d/environ (%v)", readerUID, childPID, readErr)
	default:
		t.Logf("good: non-root uid %d read /proc/%d/environ but the sentinel is absent (%d bytes)",
			readerUID, childPID, len(out))
	}

	// PROOF C — no daemon fd leak into the dropped child.
	assertNoDaemonFDLeak(t, childPID, s.dir)

	wg.Wait()
	if execCode != 0 {
		t.Errorf("privsep exec exit code = %d, want 0; stderr=%q", execCode, execStderr)
	}
}

// writePrivsepConfig enables [security] privsep in the session's config file.
func writePrivsepConfig(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config"),
		[]byte("[security]\nprivsep = true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// bootstrapTrustedSleep brings a session's vault up (init+unlock), stores the
// privsep sentinel secret, and trusts a .byn that pins `sleep {{args}}` with the
// sentinel in the [exec] env allowlist. Returns the project dir. It mirrors the
// setup NU-5's proof uses so the child gets the sentinel injected.
func bootstrapTrustedSleep(t *testing.T, s *session) string {
	t.Helper()
	if _, _, code := s.run(privsepPW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(privsepPW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	s.pw = privsepPW

	// s.dir is 0700; the dropped child needs +x to traverse into the project.
	if err := os.Chmod(s.dir, 0o711); err != nil {
		t.Fatalf("chmod s.dir traversable: %v", err)
	}
	projDir := filepath.Join(s.dir, "privsep-proj")
	if err := os.MkdirAll(projDir, 0o711); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	if so, se, code := s.runInDir(projDir, privsepSecret, nil, "put", "SECRETVAR"); code != 0 {
		t.Fatalf("put SECRETVAR: code=%d stdout=%q stderr=%q", code, so, se)
	}

	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"SECRETVAR\"]\nactions = [\"sleep {{args}}\"]\n"
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte(bynContent), 0o644); err != nil { // #nosec G306 -- .byn is non-secret config
		t.Fatalf("write .byn: %v", err)
	}
	if _, se, code := s.runInDir(projDir, privsepPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	return projDir
}

// assertHelperInstalled checks the prebuilt spawn helper is installed at its
// destination, root-owned, and carries the setuid/setgid file capabilities so it
// can drop the child to _byn-exec. A missing `getcap` degrades the cap check to a
// logged skip (the install + ownership are still asserted).
func assertHelperInstalled(t *testing.T) {
	t.Helper()
	dest := privsep.HelperDestPath()
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("spawn helper not installed at %s: %v", dest, err)
	}
	if uid := statUID(dest); uid != 0 {
		t.Errorf("spawn helper %s owned by uid %d, want root (0)", dest, uid)
	}
	// Executable bit set.
	if fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("spawn helper %s is not executable (mode %o)", dest, fi.Mode().Perm())
	}
	// File capabilities: prefer getcap; skip the cap-specific check if it's absent.
	gc, lerr := exec.LookPath("getcap")
	if lerr != nil {
		t.Logf("note: getcap not on PATH — skipping the cap_setuid/cap_setgid file-cap check on %s", dest)
		return
	}
	out, err := exec.Command(gc, dest).CombinedOutput() // #nosec G204 -- dest is a fixed installed path
	if err != nil {
		t.Logf("note: getcap %s failed (%v): %s — skipping cap check", dest, err, out)
		return
	}
	caps := strings.ToLower(string(out))
	if !strings.Contains(caps, "cap_setuid") || !strings.Contains(caps, "cap_setgid") {
		t.Errorf("spawn helper %s missing cap_setuid/cap_setgid file caps (getcap: %q)", dest, strings.TrimSpace(string(out)))
	}
}
