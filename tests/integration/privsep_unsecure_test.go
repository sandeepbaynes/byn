//go:build integration

// Privilege separation and the run on unsecure values (root-gated; skips
// cleanly off-root, like the cred-leak proof beside it).
//
// With privsep on, `byn exec` first asks the daemon to authorize a child that
// will run as _byn-exec. A .byn nobody has trusted gets no sealed value, so
// there is nothing for that isolation to protect — and running the command as
// another user would only break it (it could not read the project's files).
// The daemon therefore answers unsecure_only and the CLI runs the command
// itself, as the caller. This drives that redirect against a real provisioned
// daemon, which the daemon-level unit test cannot.

package integration

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPrivsep_UntrustedBynRunsAsCallerOnUnsecureValues(t *testing.T) {
	requireRootLinux(t)
	skipUnlessToolsPresent(t, "setcap", "setfacl", "setpriv", "id", "sh")

	s := newSession(t)
	buildHelper(t, s.bin)
	if so, se, code := s.run("", "setup"); code != 0 {
		t.Skipf("byn setup failed on this image (privsep prerequisites unavailable); stdout=%q stderr=%q", so, se)
	}
	execu := execUID(t)
	if err := os.WriteFile(filepath.Join(s.dir, "config"),
		[]byte("[security]\nprivsep = true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, se, code := s.run("", "daemon", "start", "--allow-root"); code != 0 {
		t.Fatalf("daemon start: code=%d stderr=%q", code, se)
	}
	t.Cleanup(s.stopDaemon)
	if _, _, code := s.run(privsepPW, "init", "--password-stdin"); code != 0 {
		t.Fatalf("init failed")
	}
	if _, _, code := s.run(privsepPW, "unlock", "--password-stdin"); code != 0 {
		t.Fatalf("unlock failed")
	}
	s.pw = privsepPW

	if err := os.Chmod(s.dir, 0o711); err != nil {
		t.Fatalf("chmod s.dir traversable: %v", err)
	}
	projDir := filepath.Join(s.dir, "unsecure-proj")
	if err := os.MkdirAll(projDir, 0o711); err != nil {
		t.Fatalf("mkdir projDir: %v", err)
	}
	if so, se, code := s.runInDir(projDir, privsepSecret, nil, "put", "SECRETVAR"); code != 0 {
		t.Fatalf("put SECRETVAR: code=%d stdout=%q stderr=%q", code, so, se)
	}
	if so, se, code := s.runInDir(projDir, "8080", nil, "put", "--unsecure", "PORT"); code != 0 {
		t.Fatalf("put --unsecure PORT: code=%d stdout=%q stderr=%q", code, so, se)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath,
		[]byte("[scope]\n[exec]\nenv = [\"SECRETVAR\", \"PORT\"]\nactions = [\"sh {{args}}\"]\n"), 0o644); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	const probe = `echo "uid=$(id -u) port=${PORT:-none} secret=${SECRETVAR:-none}"`
	me := strconv.Itoa(os.Getuid())

	// --- Untrusted: runs, as the caller, with PORT and without SECRETVAR. ---
	so, se, code := s.runInDir(projDir, "", nil, "exec", "--", "sh", "-c", probe)
	if code != 0 {
		t.Fatalf("untrusted exec: code=%d stdout=%q stderr=%q", code, so, se)
	}
	if want := "uid=" + me + " port=8080 secret=none"; !strings.Contains(so, want) {
		t.Errorf("untrusted exec printed %q, want %q — it must run as the caller (uid %s, not _byn-exec %d) "+
			"with the unsecure value and no sealed one", strings.TrimSpace(so), want, me, execu)
	}
	if strings.Contains(so+se, privsepSecret) {
		t.Errorf("the sealed value reached an untrusted run: stdout=%q stderr=%q", so, se)
	}
	if !strings.Contains(se, "untrusted") || !strings.Contains(se, "SECRETVAR") {
		t.Errorf("no warning naming the withheld value; stderr=%q", se)
	}

	// --- `--unsecure` asks for the same thing outright. ---
	so, se, code = s.runInDir(projDir, "", nil, "exec", "--unsecure", "--", "sh", "-c", probe)
	if code != 0 || !strings.Contains(so, "uid="+me+" port=8080 secret=none") {
		t.Errorf("exec --unsecure: code=%d stdout=%q stderr=%q", code, so, se)
	}

	// --- Trusted: the same command now runs under privilege separation, as
	// _byn-exec, with both values. The redirect is specific to the run that
	// carries no secret. ---
	if _, se, code := s.runInDir(projDir, privsepPW+"\n", nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	so, se, code = s.runInDir(projDir, "", nil, "exec", "--", "sh", "-c", probe)
	if code != 0 {
		t.Fatalf("trusted exec: code=%d stdout=%q stderr=%q", code, so, se)
	}
	if want := "uid=" + strconv.Itoa(execu) + " port=8080 secret=" + privsepSecret; !strings.Contains(so, want) {
		t.Errorf("trusted exec printed %q, want %q", strings.TrimSpace(so), want)
	}
}
