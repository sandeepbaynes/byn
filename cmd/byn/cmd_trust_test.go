package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// withCWD changes directory for the duration of a test, restoring it after.
func withCWD(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func writeDotByn(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".byn")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestDefaultBynPath_PositionalArg(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse([]string{"/explicit/path"})
	if got := defaultBynPath(fs); got != "/explicit/path" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultBynPath_FallbackToCWD(t *testing.T) {
	dir := t.TempDir()
	withCWD(t, dir)
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	_ = fs.Parse(nil)
	if filepath.Base(defaultBynPath(fs)) != ".byn" {
		t.Fatalf("want a path ending in .byn")
	}
}

func TestRunTrust_DispatchHelp(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runTrust([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestBynTargetVault_Helper(t *testing.T) {
	if v, err := bynTargetVault([]byte("[scope]\nvault = \"acme\"\n")); err != nil || v != "acme" {
		t.Fatalf("got (%q, %v)", v, err)
	}
}

// ---- grant -------------------------------------------------------------

// The headline CLI guarantee: `byn trust` sends the target vault + the
// master password to the daemon (granting is never a local write).
func TestRunTrustAdd_GrantsViaDaemonWithPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustGrantBulk, ipc.TrustGrantBulkResp{
		Results: []ipc.TrustGrantResult{{Path: "/canon/.byn", SHA256: strings.Repeat("a", 64)}},
	})
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "s3cret\n")

	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	calls := fd.callsFor(ipc.OpTrustGrantBulk)
	if len(calls) != 1 {
		t.Fatalf("expected 1 bulk grant call, got %d", len(calls))
	}
	var req ipc.TrustGrantBulkReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Vault != "a" {
		t.Errorf("vault = %q, want a (from .byn [scope])", req.Vault)
	}
	if string(req.Password) != "s3cret" {
		t.Errorf("password not forwarded to the daemon: %q", req.Password)
	}
	if len(req.Paths) != 1 || req.Paths[0] != tpath {
		t.Errorf("paths = %v, want [%q]", req.Paths, tpath)
	}
}

func TestRunTrustAdd_DaemonRejectsWrongPassword(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onErr(ipc.OpTrustGrantBulk, ipc.CodeWrongPassword, "could not authorize: wrong password")
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "wrong\n")
	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitDaemonErr {
		t.Fatalf("got %d, want exitDaemonErr", got)
	}
}

func TestRunTrustAdd_MissingFile(t *testing.T) {
	t.Setenv("BYN_TEST_DIR", t.TempDir())
	if got := runTrustAdd([]string{filepath.Join(t.TempDir(), "nope")}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_BadFlag(t *testing.T) {
	if got := runTrustAdd([]string{"--bogus"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustAdd_DaemonDown(t *testing.T) {
	noDaemon(t)
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "pw\n")
	if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitDaemonDown {
		t.Fatalf("got %d, want exitDaemonDown", got)
	}
}

// withTrustPromptPassword overrides the interactive trust-password prompt so a
// test can drive the per-vault-group path without a real TTY. It records the
// vault label each group prompted for.
func withTrustPromptPassword(t *testing.T, pw string) *[]string {
	t.Helper()
	var prompts []string
	prev := promptTrustSecure
	promptTrustSecure = func(prompt string) ([]byte, func(), error) {
		prompts = append(prompts, prompt)
		return []byte(pw), func() {}, nil
	}
	t.Cleanup(func() { promptTrustSecure = prev })
	return &prompts
}

// writeBynTree writes a .byn at <dir>/<rel> (creating parents) and returns the
// path. Used to build a recursive-trust fixture under a single root.
func writeBynTree(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, rel, ".byn")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// Owner repro (named-vault case): recursive trust over .byn files that target a
// NAMED vault, with the default vault NEVER initialized, must succeed and prompt
// ONLY for the named vault — never "default". The daemon here treats any request
// for "default"/"" as not-initialized; the CLI must never send one.
func TestRunTrustAdd_RecursiveNamedVault_NeverTouchesDefault(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, raw, &req)
		if req.Vault == "" || req.Vault == "default" {
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotInit, Message: `vault "default" is not initialized`}
		}
		return ipc.TrustGrantBulkResp{
			Results: []ipc.TrustGrantResult{{Path: req.Paths[0], SHA256: strings.Repeat("a", 64)}},
		}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "a", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "b", "[scope]\nvault = \"acme\"\n")
	prompts := withTrustPromptPassword(t, "s3cret")

	if got := runTrustAdd([]string{"--recursive", root}); got != exitOK {
		t.Fatalf("got %d, want exitOK (named-vault files must trust with default absent)", got)
	}
	// Exactly one vault group (acme); the prompt names acme, never default.
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], `"acme"`) {
		t.Fatalf("prompts = %v, want a single acme prompt", *prompts)
	}
	for _, c := range fd.callsFor(ipc.OpTrustGrantBulk) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, c.Body, &req)
		if req.Vault != "acme" {
			t.Fatalf("daemon called for vault %q, want only acme", req.Vault)
		}
	}
}

// Owner repro (empty→default case): a .byn that resolves to the (uninitialized)
// default vault must fail THAT group with a clear, actionable message — WITHOUT
// blocking the other, valid named-vault group.
func TestRunTrustAdd_DefaultGroupNotInit_DoesNotBlockNamedVault(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, raw, &req)
		if req.Vault == "" || req.Vault == "default" {
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotInit, Message: `vault "default" is not initialized`}
		}
		return ipc.TrustGrantBulkResp{
			Results: []ipc.TrustGrantResult{{Path: req.Paths[0], SHA256: strings.Repeat("b", 64)}},
		}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "named", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "nodef", "[scope]\nproject = \"p\"\n") // no vault → default
	withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		// Non-zero overall (the default group failed), but acme still trusted.
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr (one group failed)", got)
		}
	})
	// The valid named vault was trusted...
	acmeTrusted := false
	for _, c := range fd.callsFor(ipc.OpTrustGrantBulk) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, c.Body, &req)
		if req.Vault == "acme" {
			acmeTrusted = true
		}
	}
	if !acmeTrusted {
		t.Fatal("the named vault group must still be trusted despite the default group failing")
	}
	// ...and the default group surfaced an actionable error, not a silent fail.
	if !strings.Contains(out, "default vault, which isn't initialized") {
		t.Fatalf("missing actionable default-not-init message; stderr:\n%s", out)
	}
	if !strings.Contains(out, "byn init") || !strings.Contains(out, `vault = "…"`) {
		t.Fatalf("hint should suggest setting vault or running byn init; stderr:\n%s", out)
	}
}

// A malformed .byn must NOT masquerade as the default vault: it is reported as a
// per-file failure, while a sibling valid named-vault file is still trusted.
func TestRunTrustAdd_MalformedByn_NotGroupedAsDefault(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, raw, &req)
		if req.Vault == "" || req.Vault == "default" {
			t.Errorf("daemon must NOT be called for default; a parse error was wrongly grouped there")
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotInit, Message: "not init"}
		}
		return ipc.TrustGrantBulkResp{
			Results: []ipc.TrustGrantResult{{Path: req.Paths[0], SHA256: strings.Repeat("c", 64)}},
		}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "ok", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "bad", "garbage = =") // unparseable
	withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr (one file malformed)", got)
		}
	})
	if !strings.Contains(out, "malformed .byn") {
		t.Fatalf("malformed file should be reported; stderr:\n%s", out)
	}
	// The valid file's vault group was still attempted.
	if len(fd.callsFor(ipc.OpTrustGrantBulk)) != 1 {
		t.Fatalf("expected one daemon call for the valid acme group")
	}
}

// When EVERY input fails to parse/read, no daemon call happens and the command
// reports a clean failure (no phantom default group).
func TestRunTrustAdd_AllMalformed_NoDaemonCall(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustGrantBulk, ipc.TrustGrantBulkResp{})
	root := t.TempDir()
	writeBynTree(t, root, "bad", "garbage = =")
	withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr", got)
		}
	})
	if len(fd.callsFor(ipc.OpTrustGrantBulk)) != 0 {
		t.Fatal("no daemon call should be made when every file is malformed")
	}
	if !strings.Contains(out, "no .byn files could be trusted") {
		t.Fatalf("expected a clean all-failed message; stderr:\n%s", out)
	}
}

// ---- pre-flight init-state check (skip prompt for uninitialized vaults) ----

// withStatusVaults registers an OpStatus handler that reports the given vault
// names as INITIALIZED. This drives the bulk-trust pre-flight that partitions
// groups into initialized (prompted + granted) vs uninitialized (rejected
// without a prompt). Any vault NOT named here is treated as uninitialized.
func withStatusVaults(fd *fakeDaemon, names ...string) {
	summaries := make([]ipc.VaultSummary, 0, len(names))
	for _, n := range names {
		summaries = append(summaries, ipc.VaultSummary{Name: n, Initialized: true})
	}
	fd.onOK(ipc.OpStatus, ipc.StatusResp{Vaults: summaries})
}

// The headline polish: a recursive trust where one .byn targets an
// UNINITIALIZED vault (the default, never inited) and another targets an
// INITIALIZED named vault must NEVER prompt for the uninitialized vault's
// password — it is rejected up front with a clear error — while the
// initialized group is still trusted.
func TestRunTrustAdd_PreflightSkipsPromptForUninitVault(t *testing.T) {
	fd := startFakeDaemon(t)
	withStatusVaults(fd, "acme") // acme initialized; default is NOT
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, raw, &req)
		if req.Vault == "" || req.Vault == "default" {
			t.Errorf("daemon must NOT be asked to grant the uninitialized default group")
			return nil, &ipc.ErrMsg{Code: ipc.CodeNotInit, Message: "not init"}
		}
		return ipc.TrustGrantBulkResp{
			Results: []ipc.TrustGrantResult{{Path: req.Paths[0], SHA256: strings.Repeat("a", 64)}},
		}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "named", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "nodef", "[scope]\nproject = \"p\"\n") // no vault → default
	prompts := withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		// One group failed (default uninitialized) → non-zero, but acme trusted.
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr (default group rejected)", got)
		}
	})

	// The uninitialized default group was NEVER prompted: the only prompt names acme.
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], `"acme"`) {
		t.Fatalf("prompts = %v, want exactly one acme prompt (default must not be prompted)", *prompts)
	}
	// No grant call was made for the default group; exactly one (acme) was.
	calls := fd.callsFor(ipc.OpTrustGrantBulk)
	if len(calls) != 1 {
		t.Fatalf("expected exactly one grant call (acme); got %d", len(calls))
	}
	var req ipc.TrustGrantBulkReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Vault != "acme" {
		t.Fatalf("the only grant call must be for acme, got %q", req.Vault)
	}
	// The default group surfaced the clear, actionable error.
	if !strings.Contains(out, "default vault, which isn't initialized") {
		t.Fatalf("missing actionable default-not-init message; stderr:\n%s", out)
	}
	if !strings.Contains(out, "byn init") || !strings.Contains(out, `vault = "…"`) {
		t.Fatalf("hint should suggest setting vault or running byn init; stderr:\n%s", out)
	}
}

// A NAMED but uninitialized vault group is also rejected pre-flight (no prompt)
// with an actionable error naming that vault.
func TestRunTrustAdd_PreflightSkipsPromptForUninitNamedVault(t *testing.T) {
	fd := startFakeDaemon(t)
	withStatusVaults(fd, "acme") // acme initialized; "ghost" is NOT
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.TrustGrantBulkReq
		requireUnmarshal(t, raw, &req)
		if req.Vault == "ghost" {
			t.Errorf("daemon must NOT be asked to grant the uninitialized ghost group")
		}
		return ipc.TrustGrantBulkResp{
			Results: []ipc.TrustGrantResult{{Path: req.Paths[0], SHA256: strings.Repeat("a", 64)}},
		}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "ok", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "missing", "[scope]\nvault = \"ghost\"\n")
	prompts := withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr (ghost group rejected)", got)
		}
	})
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], `"acme"`) {
		t.Fatalf("prompts = %v, want exactly one acme prompt (ghost must not be prompted)", *prompts)
	}
	if !strings.Contains(out, "targets vault") || !strings.Contains(out, "ghost") ||
		!strings.Contains(out, "isn't initialized") {
		t.Fatalf("expected an actionable ghost-not-init message; stderr:\n%s", out)
	}
}

// When EVERY group targets an uninitialized vault, no prompt and no grant call
// happen at all — only the clear per-group errors.
func TestRunTrustAdd_PreflightAllUninit_NoPromptNoGrant(t *testing.T) {
	fd := startFakeDaemon(t)
	withStatusVaults(fd) // nothing initialized
	fd.on(ipc.OpTrustGrantBulk, func(raw []byte) (any, *ipc.ErrMsg) {
		t.Errorf("no grant call should be made when every vault is uninitialized")
		return ipc.TrustGrantBulkResp{}, nil
	})
	root := t.TempDir()
	writeBynTree(t, root, "a", "[scope]\nvault = \"acme\"\n")
	writeBynTree(t, root, "nodef", "[scope]\nproject = \"p\"\n") // → default
	prompts := withTrustPromptPassword(t, "s3cret")

	out := captureStderr(t, func() {
		if got := runTrustAdd([]string{"--recursive", root}); got != exitErr {
			t.Fatalf("got %d, want exitErr (all groups uninitialized)", got)
		}
	})
	if len(*prompts) != 0 {
		t.Fatalf("no prompt should occur when every vault is uninitialized; got %v", *prompts)
	}
	if n := len(fd.callsFor(ipc.OpTrustGrantBulk)); n != 0 {
		t.Fatalf("no grant call should occur; got %d", n)
	}
	if !strings.Contains(out, "isn't initialized") {
		t.Fatalf("expected per-group not-init errors; stderr:\n%s", out)
	}
}

// When the pre-flight status call itself fails (and it is NOT daemon-down),
// trust falls back to today's behavior: the grant is attempted and the daemon
// decides. Here the fake daemon has NO OpStatus handler (status → unknown-op
// error), yet the initialized vault is still trusted via the grant path.
func TestRunTrustAdd_PreflightStatusError_FallsBackToGrant(t *testing.T) {
	fd := startFakeDaemon(t)
	// Deliberately register NO OpStatus handler: the pre-flight call errors.
	fd.onOK(ipc.OpTrustGrantBulk, ipc.TrustGrantBulkResp{
		Results: []ipc.TrustGrantResult{{Path: "/x/.byn", SHA256: strings.Repeat("a", 64)}},
	})
	root := t.TempDir()
	writeBynTree(t, root, "a", "[scope]\nvault = \"acme\"\n")
	prompts := withTrustPromptPassword(t, "s3cret")

	if got := runTrustAdd([]string{"--recursive", root}); got != exitOK {
		t.Fatalf("got %d, want exitOK (fallback path still trusts via grant)", got)
	}
	// The grant WAS attempted (fallback), and the vault was prompted as before.
	if len(*prompts) != 1 || !strings.Contains((*prompts)[0], `"acme"`) {
		t.Fatalf("prompts = %v, want one acme prompt in the fallback path", *prompts)
	}
	if n := len(fd.callsFor(ipc.OpTrustGrantBulk)); n != 1 {
		t.Fatalf("expected one grant call in the fallback path; got %d", n)
	}
}

// Daemon-down at the pre-flight stage surfaces the standard daemon-down error
// and exit code — nothing can be trusted against a dead socket.
func TestRunTrustAdd_PreflightDaemonDown(t *testing.T) {
	noDaemon(t)
	root := t.TempDir()
	writeBynTree(t, root, "a", "[scope]\nvault = \"acme\"\n")
	prompts := withTrustPromptPassword(t, "s3cret")

	if got := runTrustAdd([]string{"--recursive", root}); got != exitDaemonDown {
		t.Fatalf("got %d, want exitDaemonDown", got)
	}
	if len(*prompts) != 0 {
		t.Fatalf("daemon down must not prompt; got %v", *prompts)
	}
}

// ---- untrust -----------------------------------------------------------

func TestRunUntrust_ViaDaemon(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustRemove, ipc.TrustRemoveResp{Removed: true})
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
	if n := len(fd.callsFor(ipc.OpTrustRemove)); n != 1 {
		t.Fatalf("expected 1 remove call, got %d", n)
	}
}

func TestRunUntrust_NotTrusted_StillOK(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustRemove, ipc.TrustRemoveResp{Removed: false})
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_BadFlag(t *testing.T) {
	if got := runUntrust([]string{"--bogus"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunUntrust_DaemonDown(t *testing.T) {
	noDaemon(t)
	tpath := writeDotByn(t, "x")
	if got := runUntrust([]string{tpath}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

// ---- list --------------------------------------------------------------

func TestRunTrustList_ViaDaemon(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{Entries: []ipc.TrustEntry{
		{Path: "/a/.byn", SHA256: strings.Repeat("b", 64)},
	}})
	if got := runTrustList(nil); got != exitOK {
		t.Fatalf("plain got %d", got)
	}
	if got := runTrustList([]string{"--json"}); got != exitOK {
		t.Fatalf("json got %d", got)
	}
}

func TestRunTrustList_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{})
	if got := runTrustList(nil); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_BadFlag(t *testing.T) {
	if got := runTrustList([]string{"--zz"}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrustList_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runTrustList(nil); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunTrust_ListBranch(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustList, ipc.TrustListResp{})
	if got := runTrust([]string{"list"}, cliScope{}); got != exitOK {
		t.Fatalf("list got %d", got)
	}
	if got := runTrust([]string{"ls"}, cliScope{}); got != exitOK {
		t.Fatalf("ls got %d", got)
	}
}

// ---- policy rendering (spec §4.5 footgun guard) ----------------------------

// TestRenderTrustPolicy_Actions_Wildcard verifies that a "*" actions allowlist
// renders as a loud warning with "ALL commands run re-auth-free".
func TestRenderTrustPolicy_Actions_Wildcard(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:            "/proj/.byn",
			SHA256:          strings.Repeat("a", 64),
			ActionsWildcard: true,
		})
	})
	if !strings.Contains(out, "ALL commands run re-auth-free") {
		t.Errorf("wildcard output %q missing loud warning", out)
	}
	if !strings.Contains(out, `"*"`) {
		t.Errorf("wildcard output %q missing literal *", out)
	}
}

// TestRenderTrustPolicy_Actions_List verifies that a specific list of actions
// is rendered as a comma-separated list.
func TestRenderTrustPolicy_Actions_List(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:    "/proj/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"pnpm run start", "make test"},
		})
	})
	if !strings.Contains(out, "pnpm run start") || !strings.Contains(out, "make test") {
		t.Errorf("actions-list output %q missing actions", out)
	}
}

// TestRenderTrustPolicy_Actions_None verifies that a .byn with no [exec]
// actions renders the "no [exec] actions" note.
func TestRenderTrustPolicy_Actions_None(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
		})
	})
	if !strings.Contains(out, "no [exec] actions") {
		t.Errorf("no-actions output %q missing note", out)
	}
}

// TestRenderTrustPolicy_Auth_PolicyLine verifies that non-empty [auth] overrides
// are rendered with key=value pairs.
func TestRenderTrustPolicy_Auth_PolicyLine(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
			Auth:   map[string]string{"get": "none", "delete": "always"},
		})
	})
	if !strings.Contains(out, "auth policy overrides") {
		t.Errorf("auth output %q missing 'auth policy overrides'", out)
	}
	if !strings.Contains(out, "get=none") || !strings.Contains(out, "delete=always") {
		t.Errorf("auth output %q missing key=value pairs", out)
	}
}

// TestRenderTrustPolicy_Auth_Empty verifies that an empty [auth] table is not
// rendered (no spurious "auth policy overrides:" line).
func TestRenderTrustPolicy_Auth_Empty(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
		})
	})
	if strings.Contains(out, "auth policy overrides") {
		t.Errorf("empty-auth output %q should not contain 'auth policy overrides'", out)
	}
}

// TestRenderTrustPolicy_ExecNone verifies that [auth] exec="none" renders a
// bold "exec=none — ANY command runs re-auth-free" line and does NOT print
// the misleading "no [exec] actions — every exec requires authorization" line.
func TestRenderTrustPolicy_ExecNone(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
			Auth:   map[string]string{"exec": "none"},
			// No actions pinned — exec=none replaces the "no [exec] actions" text.
		})
	})
	// Must explain that any command runs free.
	if !strings.Contains(out, "ANY command runs re-auth-free") {
		t.Errorf("exec=none output %q missing 'ANY command runs re-auth-free'", out)
	}
	// Must include exec=none in the auth policy overrides line.
	if !strings.Contains(out, "exec=none") {
		t.Errorf("exec=none output %q missing 'exec=none'", out)
	}
	// Must NOT print the misleading "every byn exec ... require authorization" line.
	if strings.Contains(out, "every byn exec") {
		t.Errorf("exec=none output %q must not print 'every byn exec ... require authorization' (that's false when exec=none)", out)
	}
}

// TestRenderTrustPolicy_ExecNoneWithActions verifies that when both [exec] actions
// are pinned AND [auth] exec="none" is set, the pinned actions take precedence
// in the rendering (exec=none is still printed in the auth overrides table).
func TestRenderTrustPolicy_ExecNoneWithActions(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:    "/proj/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"make test"},
			Auth:    map[string]string{"exec": "none"},
		})
	})
	// Pinned actions take the first branch; the actions list must still appear.
	if !strings.Contains(out, "make test") {
		t.Errorf("output %q missing 'make test' (pinned actions should appear)", out)
	}
	// exec=none still appears in the auth overrides table.
	if !strings.Contains(out, "exec=none") {
		t.Errorf("output %q missing 'exec=none' (auth overrides must still be printed)", out)
	}
}

// TestRunTrustAdd_PolicyRenderedAfterGrant verifies that the policy rendering
// is included in the CLI output after a successful single grant.
func TestRunTrustAdd_PolicyRenderedAfterGrant(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpTrustGrantBulk, ipc.TrustGrantBulkResp{
		Results: []ipc.TrustGrantResult{{
			Path:    "/canon/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"pnpm run dev"},
		}},
	})
	tpath := writeDotByn(t, "[scope]\nvault = \"a\"\n")
	withStdin(t, "s3cret\n")

	out := captureStderr(t, func() {
		if got := runTrustAdd([]string{"--password-stdin", tpath}); got != exitOK {
			t.Fatalf("got %d", got)
		}
	})
	if !strings.Contains(out, "pnpm run dev") {
		t.Errorf("output %q should contain 'pnpm run dev' from policy rendering", out)
	}
}

// ---- alias rendering (spec §4.5 footgun guard) --------------------------------

// TestRenderTrustPolicy_Aliases_Listed verifies that aliases are rendered as
// "name → value" pairs in sorted order.
func TestRenderTrustPolicy_Aliases_Listed(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
			Aliases: map[string]string{
				"test":   "npm test",
				"scrape": "npm run scrape",
			},
		})
	})
	if !strings.Contains(out, "aliases:") {
		t.Errorf("aliases output %q missing 'aliases:'", out)
	}
	if !strings.Contains(out, "test → npm test") {
		t.Errorf("aliases output %q missing 'test → npm test'", out)
	}
	if !strings.Contains(out, "scrape → npm run scrape") {
		t.Errorf("aliases output %q missing 'scrape → npm run scrape'", out)
	}
}

// TestRenderTrustPolicy_Aliases_Empty verifies that no aliases line is printed
// when there are no aliases.
func TestRenderTrustPolicy_Aliases_Empty(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:   "/proj/.byn",
			SHA256: strings.Repeat("a", 64),
		})
	})
	if strings.Contains(out, "aliases:") {
		t.Errorf("output %q should not contain 'aliases:' when none declared", out)
	}
}

// ---- LOUD action warnings (spec §4.5 footgun guard) -------------------------

// TestRenderTrustPolicy_Warning_ArgsTail verifies that a LOUD "Warning:" line is
// printed when an action contains {{args}} (permits arbitrary extra arguments).
func TestRenderTrustPolicy_Warning_ArgsTail(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:    "/proj/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"npm test {{args}}"},
		})
	})
	if !strings.Contains(out, "Warning:") {
		t.Errorf("{{args}} action output %q missing 'Warning:'", out)
	}
	if !strings.Contains(strings.ToLower(out), "arbitrary") {
		t.Errorf("{{args}} action output %q missing 'arbitrary'", out)
	}
}

// TestRenderTrustPolicy_Warning_ShellInterpreter verifies that a LOUD "Warning:"
// line is printed for a shell-interpreter-with-placeholder action.
func TestRenderTrustPolicy_Warning_ShellInterpreter(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:    "/proj/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"sh -c {{str}}"},
		})
	})
	if !strings.Contains(out, "Warning:") {
		t.Errorf("shell-interpreter action output %q missing 'Warning:'", out)
	}
	if !strings.Contains(strings.ToLower(out), "wildcard-equivalent") {
		t.Errorf("shell-interpreter action output %q missing 'wildcard-equivalent'", out)
	}
}

// TestRenderTrustPolicy_NoWarning_LiteralAction verifies that a plain literal
// action (no placeholders) generates NO loud warnings.
func TestRenderTrustPolicy_NoWarning_LiteralAction(t *testing.T) {
	out := captureStderr(t, func() {
		renderTrustPolicy(ipc.TrustGrantResult{
			Path:    "/proj/.byn",
			SHA256:  strings.Repeat("a", 64),
			Actions: []string{"npm run build"},
		})
	})
	if strings.Contains(out, "Warning:") {
		t.Errorf("literal action output %q should not contain 'Warning:'", out)
	}
}
