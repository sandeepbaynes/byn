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

// TestGrantTrustACLs_GrantsDaemonReadAndExecAccess asserts the owner-side grant
// gives the _byn daemon READ on the .byn file and _byn-exec access to the
// project dir — the two halves that let the daemon validate the file and the
// exec child run under it.
func TestGrantTrustACLs_GrantsDaemonReadAndExecAccess(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	ran := withStubACLRunner(t, nil)

	const byn = "/Users/o/proj/.byn"
	if err := grantTrustACLs(byn, "/Users/o"); err != nil {
		t.Fatalf("grantTrustACLs: %v", err)
	}
	if len(*ran) < 3 {
		t.Fatalf("expected several ACL commands, got %d: %v", len(*ran), *ran)
	}

	var fileCmds, execDirCmds int
	for _, c := range *ran {
		last := c[len(c)-1]
		joined := strings.Join(c, " ")
		// Exactly the daemon-read grant targets the .byn FILE itself.
		if last == byn {
			fileCmds++
			if !strings.Contains(joined, privsep.DaemonUser) {
				t.Errorf("file ACL must name the _byn daemon: %v", c)
			}
		}
		// _byn-exec access is granted on the project dir.
		if last == "/Users/o/proj" && strings.Contains(joined, privsep.ExecUser) {
			execDirCmds++
		}
	}
	if fileCmds == 0 {
		t.Errorf("no ACL command granted the daemon read on the .byn file; got %v", *ran)
	}
	if execDirCmds == 0 {
		t.Errorf("no ACL command granted _byn-exec on the project dir; got %v", *ran)
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
