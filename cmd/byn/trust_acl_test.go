package main

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

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

// TestGrantTrustACLs_GrantsDaemonReadAndExec asserts the owner-side grant gives
// the _byn daemon READ on the .byn AND the _byn-exec service user project
// access.
//
// The deep grant that covers pre-existing nested cache dirs is recursive, and a
// recursive walk over a real project means node_modules — it has hung `byn
// trust` before. It is allowed here only because ownerACLRun bounds it with a
// timeout: trust returning slightly under-granted is recoverable, trust never
// returning is not. The bound itself is asserted in TestOwnerACLRun_BoundsRecursiveGrants.
func TestGrantTrustACLs_GrantsDaemonReadAndExec(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	ran := withStubACLRunner(t, nil)

	const byn = "/Users/o/proj/.byn"
	if err := grantTrustACLs(byn, "/Users/o"); err != nil {
		t.Fatalf("grantTrustACLs: %v", err)
	}

	var fileCmds, execCmds int
	for _, c := range *ran {
		joined := strings.Join(c, " ")
		if c[len(c)-1] == byn {
			fileCmds++
			if !strings.Contains(joined, privsep.DaemonUser) {
				t.Errorf("file ACL must name the _byn daemon: %v", c)
			}
		}
		if strings.Contains(joined, privsep.ExecUser) {
			execCmds++
		}
	}
	if fileCmds == 0 {
		t.Errorf("no ACL command granted the daemon read on the .byn file; got %v", *ran)
	}
	if execCmds == 0 {
		t.Errorf("no ACL command granted _byn-exec project access; got %v", *ran)
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

// A recursive ACL over a real project walks node_modules, and has hung `byn
// trust` in the past. The grant is allowed to be recursive only because it
// cannot run unbounded; this pins the bound so removing it fails loudly rather
// than reintroducing a hang nobody notices until a large repo hits it.
func TestOwnerACLRun_BoundsRecursiveGrants(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("ACL grants are no-ops on this platform")
	}
	if recursiveACLTimeout <= 0 {
		t.Fatal("recursive ACL grants must be bounded; an unbounded walk hangs byn trust")
	}
	if aclTimeout <= 0 {
		t.Fatal("ACL grants must be bounded")
	}

	// A command that never returns must be stopped rather than hang the caller.
	start := time.Now()
	err := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		return exec.CommandContext(ctx, "sleep", "60").Run()
	}()
	if err == nil {
		t.Fatal("expected the bounded command to be stopped")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bounded command ran for %s; the timeout is not being applied", elapsed)
	}
}
