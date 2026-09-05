package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

func neverBlocked(string) bool  { return false }
func alwaysBlocked(string) bool { return true }

func TestFDACheck_Granted(t *testing.T) {
	// Granted is OK even with a trusted .byn the prober would call blocked:
	// the grant is the answer, so nothing else is consulted.
	c := fdaCheck(true, []string{"/Users/o/Documents/p/.byn"}, alwaysBlocked)
	if c.Name != fdaCheckName || c.Severity != "ok" {
		t.Fatalf("got %+v", c)
	}
	if !strings.Contains(c.Detail, "granted") {
		t.Errorf("detail = %q", c.Detail)
	}
}

func TestFDACheck_NotGrantedNothingBlocked(t *testing.T) {
	// FDA is not needed for a project outside the protected folders. Reporting
	// that as a failure would leave doctor permanently red on a healthy machine.
	c := fdaCheck(false, []string{"/Users/o/code/p/.byn"}, neverBlocked)
	if c.Severity != "ok" {
		t.Fatalf("severity = %q, want ok: %+v", c.Severity, c)
	}
	if !strings.Contains(c.Detail, "not granted") {
		t.Errorf("detail should state the FDA state: %q", c.Detail)
	}
}

func TestFDACheck_NoTrustedFilesAtAll(t *testing.T) {
	c := fdaCheck(false, nil, alwaysBlocked)
	if c.Severity != "ok" {
		t.Fatalf("severity = %q, want ok (nothing to block): %+v", c.Severity, c)
	}
}

func TestFDACheck_BlockedFails(t *testing.T) {
	blocked := "/Users/o/Documents/p/.byn"
	c := fdaCheck(false, []string{"/Users/o/code/q/.byn", blocked}, func(p string) bool {
		return p == blocked
	})
	if c.Severity != "fail" {
		t.Fatalf("severity = %q, want fail: %+v", c.Severity, c)
	}
	if !strings.Contains(c.Detail, blocked) {
		t.Errorf("detail must name the blocked file, got %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "a trusted .byn") {
		t.Errorf("single blocked file should read singular, got %q", c.Detail)
	}
	// Both remedies, because moving the project needs no privileges at all.
	for _, want := range []string{"Full Disk Access", "~/Documents", "kickstart"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail missing %q: %q", want, c.Detail)
		}
	}
}

func TestFDACheck_BlockedPluralCounts(t *testing.T) {
	c := fdaCheck(false, []string{"/a/.byn", "/b/.byn", "/c/.byn"}, alwaysBlocked)
	if c.Severity != "fail" {
		t.Fatalf("severity = %q, want fail", c.Severity)
	}
	if !strings.Contains(c.Detail, "3 trusted .byn files") {
		t.Errorf("detail should count the blocked files, got %q", c.Detail)
	}
	if !strings.Contains(c.Detail, "/a/.byn") {
		t.Errorf("detail should give an example, got %q", c.Detail)
	}
}

func TestTrustedBynPaths(t *testing.T) {
	dir := t.TempDir()
	// Missing store → no paths, no error.
	if got := trustedBynPaths(dir); len(got) != 0 {
		t.Fatalf("missing store: got %v", got)
	}
	body, err := json.Marshal(trust.Store{Records: []trust.Record{
		{Path: "/x/.byn"}, {Path: "/y/.byn"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(filepath.Join(dir, trust.Filename), body, 0o600); werr != nil {
		t.Fatal(werr)
	}
	got := trustedBynPaths(dir)
	if len(got) != 2 || got[0] != "/x/.byn" || got[1] != "/y/.byn" {
		t.Fatalf("got %v", got)
	}
	// An unreadable/corrupt store is not this check's business: report nothing
	// rather than turning a trust-store fault into an FDA fault.
	if werr := os.WriteFile(filepath.Join(dir, trust.Filename), []byte("{"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := trustedBynPaths(dir); len(got) != 0 {
		t.Fatalf("corrupt store: got %v", got)
	}
}

func TestTCCBlocked(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "readable.byn")
	if err := os.WriteFile(readable, []byte("[scope]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tccBlocked(readable) {
		t.Error("a readable file must not be reported as blocked")
	}
	// A deleted project is ENOENT, and Full Disk Access would not bring it back.
	if tccBlocked(filepath.Join(dir, "gone.byn")) {
		t.Error("a missing file must not be reported as blocked")
	}
	// A POSIX/ACL denial is EACCES, not the EPERM of a TCC denial — granting
	// FDA would not fix it, so it must not be attributed to FDA.
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny")
	}
	noPerm := filepath.Join(dir, "noperm.byn")
	if err := os.WriteFile(noPerm, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if tccBlocked(noPerm) {
		t.Error("EACCES must not be reported as a TCC block")
	}
}

func TestFDAChecks_OnlyOnDarwinWithPrivsep(t *testing.T) {
	d := &Daemon{cfg: Config{Dir: t.TempDir()}}
	if got := d.fdaChecks(); got != nil {
		t.Fatalf("privsep off: got %+v", got)
	}
	d.cfg.Privsep = true
	got := d.fdaChecks()
	if runtime.GOOS != "darwin" {
		if got != nil {
			t.Fatalf("non-darwin: got %+v", got)
		}
		return
	}
	if len(got) != 1 || got[0].Name != fdaCheckName {
		t.Fatalf("darwin+privsep: got %+v", got)
	}
}

func TestHandleDoctor_FDALinePresence(t *testing.T) {
	d, c := startTestDaemon(t)
	var r ipc.DoctorResp
	if err := c.Call(ipc.OpDoctor, ipc.DoctorReq{}, &r); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	var found bool
	for _, ch := range r.Checks {
		if ch.Name == fdaCheckName {
			found = true
		}
	}
	// The test daemon runs without privsep, so the line must be absent —
	// the same guard `byn status` uses for its "fda:" line.
	if found != (runtime.GOOS == "darwin" && d.cfg.Privsep) {
		t.Fatalf("fda check present=%v with privsep=%v on %s", found, d.cfg.Privsep, runtime.GOOS)
	}
}
