package main

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/privsep"
)

// withStubACLRunner swaps ownerACLRun for a recorder (optionally returning fn's
// error) and restores it after the test. Returns a pointer to the recorded
// command list.
func withStubACLRunner(t *testing.T, fn func(name string, args ...string) error) *[][]string {
	t.Helper()
	var ran [][]string
	old := ownerACLRun
	ownerACLRun = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		if fn != nil {
			return fn(name, args...)
		}
		return nil
	}
	t.Cleanup(func() { ownerACLRun = old })
	return &ran
}

// TestGrantTrustACLs_GrantsDaemonReadNoRecursion asserts the owner-side grant
// gives the _byn daemon READ on the .byn file and traversal to reach it — and
// crucially runs NO recursive ACL command. A recursive grant (chmod -R /
// setfacl -R) on a real project would walk node_modules and hang; that bug is
// guarded here.
func TestGrantTrustACLs_GrantsDaemonReadNoRecursion(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	ran := withStubACLRunner(t, nil)

	const byn = "/Users/o/proj/.byn"
	if err := grantTrustACLs(byn, "/Users/o"); err != nil {
		t.Fatalf("grantTrustACLs: %v", err)
	}

	var fileCmds int
	for _, c := range *ran {
		// No recursive grants — they would traverse node_modules and hang.
		for _, a := range c {
			if a == "-R" {
				t.Errorf("trust grant must never run a recursive ACL: %v", c)
			}
		}
		if c[len(c)-1] == byn {
			fileCmds++
			if !strings.Contains(strings.Join(c, " "), privsep.DaemonUser) {
				t.Errorf("file ACL must name the _byn daemon: %v", c)
			}
		}
		// The exec user must NOT be granted here (that grant is recursive and
		// belongs to the exec model, not trust).
		if strings.Contains(strings.Join(c, " "), privsep.ExecUser) {
			t.Errorf("trust grant must not touch _byn-exec: %v", c)
		}
	}
	if fileCmds == 0 {
		t.Errorf("no ACL command granted the daemon read on the .byn file; got %v", *ran)
	}
}

// TestGrantTrustACLs_PropagatesRunnerError surfaces the first ACL failure so the
// caller can roll the grant back.
func TestGrantTrustACLs_PropagatesRunnerError(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	sentinel := errors.New("boom")
	withStubACLRunner(t, func(string, ...string) error { return sentinel })
	if err := grantTrustACLs("/Users/o/proj/.byn", "/Users/o"); !errors.Is(err, sentinel) {
		t.Fatalf("grantTrustACLs err = %v, want sentinel", err)
	}
}

// TestRevokeTrustACLs_BestEffort revokes both ACLs and never propagates an error
// (an orphaned ACL is harmless and self-heals), even when the runner fails.
func TestRevokeTrustACLs_BestEffort(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	ran := withStubACLRunner(t, func(string, ...string) error { return errors.New("ignored") })
	revokeTrustACLs("/Users/o/proj/.byn", "/Users/o") // must not panic or fail
	if len(*ran) == 0 {
		t.Fatal("revokeTrustACLs ran no commands")
	}
}
