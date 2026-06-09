//go:build integration

// Slice 6 tests: .byn discovery + TOFU trust.
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runInDir is run() but with the child CWD overridden, since .byn
// discovery walks parents from CWD.
func (s *session) runInDir(cwd, stdin string, env []string, args ...string) (string, string, int) {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...) //nolint:gosec // test harness
	cmd.Dir = cwd
	cmd.Env = append([]string{"BYN_DIR=" + s.dir, "HOME=" + cwd, "USER=tester"}, env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			s.t.Fatalf("runInDir %v: %v", args, err)
		}
	}
	return stdoutBuf.String(), stderrBuf.String(), code
}

func TestE2E_Exec_UntrustedBynFails(t *testing.T) {
	s := bootstrapUnlocked(t)
	// Create a project root with a .byn file.
	projDir := filepath.Join(s.dir, "myproj")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(projDir, ".byn"),
		[]byte("[scope]\nproject = \"alpha\"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write .byn: %v", err)
	}
	// Pre-create project so exec would otherwise succeed.
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	// byn exec must hard-fail on an untrusted .byn before injecting anything.
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "true")
	if code == 0 {
		t.Fatalf("exec on an untrusted .byn should fail; got code 0")
	}
	if !strings.Contains(stderr, "untrusted") || !strings.Contains(stderr, "byn trust") {
		t.Fatalf("rejection should mention untrusted + trust command:\n%s", stderr)
	}
	// But a non-exec command must pass through — only exec gates on trust.
	if _, _, code := s.runInDir(projDir, "", nil, "list", "--json"); code != 0 {
		t.Fatalf("list on an untrusted .byn should pass through; got code %d", code)
	}
}

func TestE2E_Discovery_TrustThenList(t *testing.T) {
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "myproj2")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotBynPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotBynPath, []byte("[scope]\nproject = \"alpha\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	if _, _, code := s.runInDir(projDir, "correct-horse-battery-staple\n", nil,
		"trust", "--password-stdin", dotBynPath); code != 0 {
		t.Fatalf("trust failed")
	}
	// Now listing in projDir without --project should target "alpha".
	if so, se, code := s.runInDir(projDir, "v1", nil, "put", "K"); code != 0 {
		t.Fatalf("put in scope failed code=%d\nstdout=%q\nstderr=%q", code, so, se)
	}
	stdout, _, code := s.runInDir(projDir, "", nil, "get", "K")
	if code != 0 {
		t.Fatalf("get exit %d", code)
	}
	if stdout != "v1" {
		t.Fatalf("get K via discovered scope = %q, want %q", stdout, "v1")
	}
	// Trust list should include the file.
	stdout, _ = s.mustRun("", "trust", "list", "--json")
	var records []map[string]string
	if err := json.Unmarshal([]byte(stdout), &records); err != nil {
		t.Fatalf("trust list --json: %v\n%s", err, stdout)
	}
	expect, _ := filepath.EvalSymlinks(dotBynPath)
	found := false
	for _, r := range records {
		if r["path"] == expect || r["path"] == dotBynPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("trust list did not include %s (or canonical %s):\n%s",
			dotBynPath, expect, stdout)
	}
}

func TestE2E_Discovery_TamperedReprompts(t *testing.T) {
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "tampertest")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte("[scope]\nproject = \"alpha\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	// Trust it once (granting now requires the master password).
	if _, _, code := s.runInDir(projDir, "correct-horse-battery-staple\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust failed")
	}
	// Tamper.
	if err := os.WriteFile(dotPath, []byte("[scope]\nproject = \"evil\"\n"), 0o600); err != nil {
		t.Fatalf("retmper: %v", err)
	}
	// A changed-since-trusted file must hard-fail exec (no silent re-trust).
	_, stderr, code := s.runInDir(projDir, "", nil, "exec", "--", "true")
	if code == 0 {
		t.Fatalf("exec on a changed .byn should fail")
	}
	if !strings.Contains(stderr, "CHANGED") {
		t.Fatalf("changed-file rejection should say CHANGED:\n%s", stderr)
	}
}

// A trusted .byn lets exec through — it injects the scope and runs the child.
func TestE2E_Exec_TrustedBynRuns(t *testing.T) {
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "exectrust")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath, []byte("[scope]\nproject = \"alpha\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	if _, _, code := s.runInDir(projDir, "correct-horse-battery-staple\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust failed")
	}
	stdout, se, code := s.runInDir(projDir, "", nil, "exec", "--", "/bin/echo", "ranok")
	if code != 0 {
		t.Fatalf("exec on a trusted .byn should run; code=%d stderr=%q", code, se)
	}
	if !strings.Contains(stdout, "ranok") {
		t.Fatalf("child output missing; stdout=%q", stdout)
	}
}

// The .byn [exec] env allowlist injects only the listed vars into the child.
func TestE2E_Exec_EnvAllowlist(t *testing.T) {
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "allowlist")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dotPath := filepath.Join(projDir, ".byn")
	if err := os.WriteFile(dotPath,
		[]byte("[scope]\nproject = \"alpha\"\n[exec]\nenv = [\"X\"]\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	// Two vars in scope; only X is allowlisted.
	if _, _, code := s.runInDir(projDir, "valx", nil, "put", "X"); code != 0 {
		t.Fatalf("put X failed")
	}
	if _, _, code := s.runInDir(projDir, "valy", nil, "put", "Y"); code != 0 {
		t.Fatalf("put Y failed")
	}
	if _, _, code := s.runInDir(projDir, "correct-horse-battery-staple\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust failed")
	}
	stdout, se, code := s.runInDir(projDir, "", nil,
		"exec", "--", "/bin/sh", "-c", `printf "X=%s|Y=%s" "$X" "$Y"`)
	if code != 0 {
		t.Fatalf("exec failed code=%d stderr=%q", code, se)
	}
	if stdout != "X=valx|Y=" {
		t.Fatalf("allowlist not applied; stdout=%q want %q", stdout, "X=valx|Y=")
	}
}

func TestE2E_Discovery_EmptyBynStopsWalk(t *testing.T) {
	s := bootstrapUnlocked(t)
	parent := filepath.Join(s.dir, "parent")
	child := filepath.Join(parent, "child")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Parent .byn points to alpha.
	if err := os.WriteFile(
		filepath.Join(parent, ".byn"),
		[]byte("[scope]\nproject = \"alpha\"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write parent: %v", err)
	}
	// Child .byn is EMPTY → stops the walk; default scope used.
	if err := os.WriteFile(filepath.Join(child, ".byn"), []byte{}, 0o600); err != nil {
		t.Fatalf("write child: %v", err)
	}
	if _, _, code := s.run("", "project", "create", "alpha"); code != 0 {
		t.Fatalf("project create alpha failed")
	}
	// From the child, scope should be default — putting K must NOT
	// land in alpha.
	if _, _, code := s.runInDir(child, "v1", nil, "put", "K"); code != 0 {
		t.Fatalf("put in default scope failed")
	}
	// Verify alpha is empty.
	stdout, _ := s.mustRun("", "--project", "alpha", "list", "--json")
	var entries []map[string]any
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("alpha list: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("alpha should be empty (empty .byn should stop walk); got %d entries", len(entries))
	}
}

func TestE2E_Discovery_NoDiscoveryFlag(t *testing.T) {
	s := bootstrapUnlocked(t)
	projDir := filepath.Join(s.dir, "nodisc")
	if err := os.MkdirAll(projDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(projDir, ".byn"),
		[]byte("[scope]\nproject = \"evil\"\n"),
		0o600,
	); err != nil {
		t.Fatalf("write: %v", err)
	}
	// --no-discovery should ignore the file even if untrusted.
	if _, _, code := s.runInDir(projDir, "v1", nil, "--no-discovery", "put", "K"); code != 0 {
		t.Fatalf("put with --no-discovery failed")
	}
	// And the value should be in the default scope.
	stdout, _ := s.mustRun("", "get", "K")
	if stdout != "v1" {
		t.Fatalf("get K (default scope, --no-discovery on put) = %q", stdout)
	}
}
