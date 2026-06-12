package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// ---- byn trust diff CLI tests -----------------------------------------------

// TestRunTrustDiff_NoPath_UsageError verifies that `byn trust diff` with no
// path argument prints a usage error and exits with exitErr.
func TestRunTrustDiff_NoPath_UsageError(t *testing.T) {
	if got := runTrustDiff(nil); got != exitErr {
		t.Fatalf("no-path got %d, want exitErr", got)
	}
	if got := runTrustDiff([]string{}); got != exitErr {
		t.Fatalf("empty-args got %d, want exitErr", got)
	}
}

// TestRunTrustDiff_DaemonDown verifies the daemon-down exit code (2).
func TestRunTrustDiff_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runTrustDiff([]string{"/some/.byn"}); got != exitDaemonDown {
		t.Fatalf("got %d, want exitDaemonDown(%d)", got, exitDaemonDown)
	}
}

// TestRunTrustDiff_NotTrusted_DaemonErr verifies a not_found response from the
// daemon maps to exitDaemonErr (3).
func TestRunTrustDiff_NotTrusted_DaemonErr(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpTrustDiff, ipc.CodeNotFound, "not trusted")
	if got := runTrustDiff([]string{"/x/.byn"}); got != exitDaemonErr {
		t.Fatalf("got %d, want exitDaemonErr", got)
	}
}

// TestRunTrustDiff_ContentChanged_PrintsDiffAndExits1 verifies that a content
// diff is printed to stdout and the exit code is 1 (exitErr).
func TestRunTrustDiff_ContentChanged_PrintsDiffAndExits1(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustDiff, ipc.TrustDiffResp{
		Path:        "/proj/.byn",
		Trusted:     true,
		OldSnapshot: []byte("[scope]\nproject = \"svc\"\n"),
		NewContent:  []byte("[scope]\nproject = \"svc\"\nenv = \"prod\"\n"),
	})

	out := captureStdout(t, func() {
		if got := runTrustDiff([]string{"/proj/.byn"}); got != exitErr {
			t.Errorf("got %d, want exitErr(1) for changed content", got)
		}
	})

	// Unified diff must contain + and - lines.
	if !strings.Contains(out, "+") {
		t.Errorf("diff output %q missing + lines", out)
	}
	if !strings.Contains(out, "--- trusted") {
		t.Errorf("diff output %q missing '--- trusted' header", out)
	}
	if !strings.Contains(out, "+++ current") {
		t.Errorf("diff output %q missing '+++ current' header", out)
	}
}

// TestRunTrustDiff_MTimeOnly_PrintsHintAndExits1 verifies that a mtime-only
// change prints the touch hint and exits 1.
func TestRunTrustDiff_MTimeOnly_PrintsHintAndExits1(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustDiff, ipc.TrustDiffResp{
		Path:             "/proj/.byn",
		Trusted:          true,
		OldSnapshot:      []byte("[scope]\nproject = \"svc\"\n"),
		NewContent:       []byte("[scope]\nproject = \"svc\"\n"),
		MTimeChangedOnly: true,
	})

	out := captureStderr(t, func() {
		if got := runTrustDiff([]string{"/proj/.byn"}); got != exitErr {
			t.Errorf("got %d, want exitErr(1) for mtime-only", got)
		}
	})

	if !strings.Contains(out, "modification time changed") {
		t.Errorf("mtime hint output %q missing 'modification time changed'", out)
	}
	if !strings.Contains(out, "byn trust") {
		t.Errorf("mtime hint output %q missing 're-trust' hint", out)
	}
}

// TestRunTrustDiff_Identical_ExitsOK verifies that an identical file exits 0.
func TestRunTrustDiff_Identical_ExitsOK(t *testing.T) {
	fd := startFakeDaemon(t)
	content := []byte("[scope]\nproject = \"svc\"\n")
	fd.onOK(ipc.OpTrustDiff, ipc.TrustDiffResp{
		Path:        "/proj/.byn",
		Trusted:     true,
		OldSnapshot: content,
		NewContent:  content,
	})

	if got := runTrustDiff([]string{"/proj/.byn"}); got != exitOK {
		t.Fatalf("got %d, want exitOK(0) for identical content", got)
	}
}

// TestRunTrustDiff_RelativePath_AbsolutizedBeforeSend verifies that a relative
// path is made absolute against the CLIENT's CWD before being sent to the
// daemon. The daemon resolves relative paths against ITS OWN cwd, so sending a
// raw relative path would diff the wrong file. Regression for the "trust diff
// resolves against the daemon dir, not the process dir" bug.
func TestRunTrustDiff_RelativePath_AbsolutizedBeforeSend(t *testing.T) {
	fd := startFakeDaemon(t)
	content := []byte("[scope]\nproject = \"svc\"\n")
	fd.onOK(ipc.OpTrustDiff, ipc.TrustDiffResp{
		Path:        "/proj/.byn",
		Trusted:     true,
		OldSnapshot: content,
		NewContent:  content,
	})

	rel := "apps/chat-window/.byn"
	want, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}

	// Identical content → exitOK; we only assert the path that was sent.
	if got := runTrustDiff([]string{rel}); got != exitOK {
		t.Fatalf("got exit %d, want exitOK", got)
	}

	calls := fd.callsFor(ipc.OpTrustDiff)
	if len(calls) != 1 {
		t.Fatalf("got %d TrustDiff calls, want 1", len(calls))
	}
	var req ipc.TrustDiffReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Path != want {
		t.Errorf("daemon received Path %q, want absolutized %q", req.Path, want)
	}
}

// TestRunTrust_DiffBranch verifies that "byn trust diff" dispatches to
// runTrustDiff (daemon-down path: diff without a running daemon = exitDaemonDown).
func TestRunTrust_DiffBranch(t *testing.T) {
	noDaemon(t)
	if got := runTrust([]string{"diff", "/x/.byn"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("trust diff dispatch got %d, want exitDaemonDown", got)
	}
}

// ---- EnvWildcard rendering in renderTrustPolicy ----------------------------

func TestRenderTrustPolicy_EnvWildcard_ShowsLine(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:        "/proj/.byn",
			SHA256:      strings.Repeat("a", 64),
			EnvWildcard: true,
		})
	})
	if !strings.Contains(out, `"*"`) {
		t.Errorf("env wildcard output %q missing '*'", out)
	}
	if !strings.Contains(out, "ALL scoped vars are injected") {
		t.Errorf("env wildcard output %q missing footgun message", out)
	}
}

func TestRenderTrustPolicy_NoEnvWildcard_NoLine(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
		})
	})
	if strings.Contains(out, "ALL scoped vars") {
		t.Errorf("no-wildcard output %q should not contain env wildcard line", out)
	}
}
