package main

// cmd_exec_alias_test.go — CLI tests for NU-2.1 alias exec grammar and
// ResolvedArgv handling.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// noSuchBin is a sentinel binary name that must not exist on any CI/dev machine.
const noSuchBin = "byn-no-such-binary-zzz"

// ── grammar dispatch: alias form vs direct form ──────────────────────────────

// TestRunExec_AliasForm_DispatchesSetsAlias: when the first arg is not "--"
// and not a flag (with a non-empty SourcePath), the alias form sends Alias=NAME
// and Path=SourcePath to the daemon.
func TestRunExec_AliasForm_DispatchesSetsAlias(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		// Use a non-existent binary so LookPath fails (prevents syscall.Exec).
		ResolvedArgv: []string{noSuchBin},
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	// Alias form: first arg is non-"--", non-flag → alias dispatch.
	_ = runExec([]string{"myalias"}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Alias != "myalias" {
		t.Errorf("Alias = %q, want %q", req.Alias, "myalias")
	}
	if req.Path != bynPath {
		t.Errorf("Path = %q, want %q", req.Path, bynPath)
	}
	if len(req.Argv) != 0 {
		t.Errorf("Argv = %v, want empty (no extra args)", req.Argv)
	}
}

// TestRunExec_AliasForm_ExtraArgsSentAsArgv: extra args after the alias name
// are sent as Argv.
func TestRunExec_AliasForm_ExtraArgsSentAsArgv(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin, "--watch"},
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	_ = runExec([]string{"myalias", "--watch"}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Alias != "myalias" {
		t.Errorf("Alias = %q, want %q", req.Alias, "myalias")
	}
	if len(req.Argv) != 1 || req.Argv[0] != "--watch" {
		t.Errorf("Argv = %v, want [--watch]", req.Argv)
	}
}

// TestRunExec_DirectForm_SetsArgvNotAlias: "byn exec -- cmd" sends Argv
// (full argv) and leaves Alias empty.
func TestRunExec_DirectForm_SetsArgvNotAlias(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin},
	})

	_ = runExec([]string{"--", noSuchBin}, cliScope{})

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Alias != "" {
		t.Errorf("Alias = %q, want empty for direct form", req.Alias)
	}
	if len(req.Argv) != 1 || req.Argv[0] != noSuchBin {
		t.Errorf("Argv = %v, want [%s]", req.Argv, noSuchBin)
	}
}

// TestRunExec_AliasVsDirectShadow_DashDash: `byn exec -- test` uses direct
// form (Alias=""), even if a .byn is in scope. The "--" forces direct.
func TestRunExec_AliasVsDirectShadow_DashDash(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin},
	})

	// Even with a SourcePath, the "--" forces direct form.
	scope := cliScope{SourcePath: "/proj/.byn"}
	_ = runExec([]string{"--", noSuchBin}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Alias != "" {
		t.Errorf("direct form (--): Alias = %q, want empty", req.Alias)
	}
	if len(req.Argv) != 1 || req.Argv[0] != noSuchBin {
		t.Errorf("direct form (--): Argv = %v, want [%s]", req.Argv, noSuchBin)
	}
}

// TestRunExec_AliasForm_NoByn_Error: alias form without a .byn in scope
// prints the "no .byn in scope" error and returns exitErr.
func TestRunExec_AliasForm_NoByn_Error(t *testing.T) {
	// No daemon needed — the alias form fails before any IPC.
	noDaemon(t)
	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"myalias"}, cliScope{SourcePath: ""})
	})
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr (%d)", rc, exitErr)
	}
	if !strings.Contains(errOut, "no .byn") {
		t.Errorf("stderr = %q, want 'no .byn' message", errOut)
	}
	if !strings.Contains(errOut, "[aliases]") {
		t.Errorf("stderr = %q, want '[aliases]' in message", errOut)
	}
}

// ── ResolvedArgv contract: CLI uses the daemon's argv ─────────────────────────

// TestRunExec_AliasForm_ResolvedArgvUsed: when the daemon returns ResolvedArgv,
// the CLI uses it for LookPath. If ResolvedArgv[0] doesn't exist, the error
// message names the resolved binary (not the alias).
func TestRunExec_AliasForm_ResolvedArgvUsed(t *testing.T) {
	fd := startFakeDaemon(t)
	// Daemon returns a ResolvedArgv with a non-existent binary (distinct name).
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{"byn-no-such-resolved-binary-yyy", "--flag"},
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"alias-name"}, scope)
	})
	// LookPath failure → exitErr; the error should mention the resolved binary.
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr (LookPath failure)", rc)
	}
	// The error must name the resolved binary, not "alias-name".
	if !strings.Contains(errOut, "byn-no-such-resolved-binary-yyy") {
		t.Errorf("stderr = %q, want resolved binary name in error", errOut)
	}
}

// TestRunExec_DirectForm_ResolvedArgvOverrides: even for direct exec, if the
// daemon returns ResolvedArgv, the CLI uses it for LookPath.
func TestRunExec_DirectForm_ResolvedArgvOverrides(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin},
	})

	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"--", noSuchBin}, cliScope{})
	})
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr", rc)
	}
	if !strings.Contains(errOut, noSuchBin) {
		t.Errorf("stderr = %q, want %q in error", errOut, noSuchBin)
	}
}

// TestRunExec_AliasForm_NoResolvedArgv_Error: if the daemon returns a success
// response for an alias exec but omits ResolvedArgv, the CLI fails fast with
// a clear error (daemon contract violation).
func TestRunExec_AliasForm_NoResolvedArgv_Error(t *testing.T) {
	fd := startFakeDaemon(t)
	// Misbehaving daemon: success but no ResolvedArgv.
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: nil,
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"alias-name"}, scope)
	})
	if rc != exitErr {
		t.Errorf("rc = %d, want exitErr", rc)
	}
	if !strings.Contains(errOut, "ResolvedArgv") {
		t.Errorf("stderr = %q, want 'ResolvedArgv' in error message", errOut)
	}
}

// ── not_found rendering ───────────────────────────────────────────────────────

// TestRunExec_AliasNotFound_RendersMessage: CodeNotFound from the daemon
// (alias not defined) is rendered to stderr and exits with exitDaemonErr.
func TestRunExec_AliasNotFound_RendersMessage(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.on(ipc.OpExecFetch, func(_ []byte) (any, *ipc.ErrMsg) {
		return nil, &ipc.ErrMsg{
			Code:    ipc.CodeNotFound,
			Message: `alias "no-such" is not defined in /proj/.byn [aliases]; available: start, myalias`,
		}
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	var rc int
	errOut := captureStderr(t, func() {
		rc = runExec([]string{"no-such"}, scope)
	})
	if rc != exitDaemonErr {
		t.Errorf("rc = %d, want exitDaemonErr (%d)", rc, exitDaemonErr)
	}
	if !strings.Contains(errOut, "not defined") {
		t.Errorf("stderr = %q, want 'not defined' in message", errOut)
	}
	if !strings.Contains(errOut, "no-such") {
		t.Errorf("stderr = %q, want alias name in message", errOut)
	}
}

// ── wire body for alias exec ──────────────────────────────────────────────────

// TestRunExec_AliasWireBody: verifies the full wire body for an alias exec
// request — Path from scope, Alias set, Argv as extra args only, Scope fields.
func TestRunExec_AliasWireBody(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin},
	})

	bynPath := "/proj/.byn"
	scope := cliScope{
		SourcePath: bynPath,
		Vault:      "myvault",
		Project:    "myproj",
		Env:        "dev",
	}
	// Alias "deploy" with extra args.
	_ = runExec([]string{"deploy", "--env", "prod"}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec.fetch call, got %d", len(calls))
	}
	var req ipc.ExecFetchReq
	requireUnmarshal(t, calls[0].Body, &req)
	if req.Alias != "deploy" {
		t.Errorf("Alias = %q, want %q", req.Alias, "deploy")
	}
	if req.Path != bynPath {
		t.Errorf("Path = %q, want %q", req.Path, bynPath)
	}
	if req.Scope.Vault != "myvault" || req.Scope.Project != "myproj" || req.Scope.Env != "dev" {
		t.Errorf("Scope = %+v, want myvault/myproj/dev", req.Scope)
	}
	wantArgv := []string{"--env", "prod"}
	if len(req.Argv) != len(wantArgv) {
		t.Fatalf("Argv len = %d, want %d", len(req.Argv), len(wantArgv))
	}
	for i, a := range wantArgv {
		if req.Argv[i] != a {
			t.Errorf("Argv[%d] = %q, want %q", i, req.Argv[i], a)
		}
	}
}

// TestRunExec_AliasForm_MissingBinary: daemon returns ResolvedArgv but the
// binary doesn't exist — LookPath fails and returns exitErr.
func TestRunExec_AliasForm_MissingBinary(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin, "arg1"},
	})

	bynPath := "/proj/.byn"
	scope := cliScope{SourcePath: bynPath}
	rc := runExec([]string{"myalias", "arg1"}, scope)
	if rc != exitErr {
		t.Errorf("missing binary: rc = %d, want exitErr (%d)", rc, exitErr)
	}
}

// ── exec.fetch body: Argv omitted for alias with no extra args ────────────────

// TestRunExec_AliasForm_NoExtraArgs_ArgvOmitted: when alias form has no extra
// args, Argv field should be nil/empty (omitempty on the wire).
func TestRunExec_AliasForm_NoExtraArgs_ArgvOmitted(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpExecFetch, ipc.ExecFetchResp{
		ResolvedArgv: []string{noSuchBin},
	})

	scope := cliScope{SourcePath: "/proj/.byn"}
	_ = runExec([]string{"start"}, scope)

	calls := fd.callsFor(ipc.OpExecFetch)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	// Parse the raw JSON to verify argv is absent or empty.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(calls[0].Body, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if av, ok := raw["argv"]; ok {
		// If present it must be null or [].
		var arr []string
		if err := json.Unmarshal(av, &arr); err != nil || len(arr) != 0 {
			t.Errorf("argv = %s, want absent or empty array", av)
		}
	}
	// Alias field must be set.
	if a, ok := raw["alias"]; !ok || string(a) != `"start"` {
		t.Errorf("alias in raw body = %s, want \"start\"", a)
	}
}

// ── help text contains both grammars ─────────────────────────────────────────

// TestRunExec_UsageHasBothGrammars: when `byn exec` is invoked without any
// args (direct form, no separator found), the usage message mentions "--".
func TestRunExec_UsageHasBothGrammars(t *testing.T) {
	// No daemon needed — fails before IPC.
	noDaemon(t)
	var rc int
	errOut := captureStderr(t, func() {
		// Empty args → direct form code path (no args[0]) → no "--" found.
		rc = runExec([]string{}, cliScope{})
	})
	if rc != exitErr {
		t.Errorf("no-args rc = %d, want exitErr", rc)
	}
	// The error or hint must mention "--".
	if !strings.Contains(errOut, "--") {
		t.Errorf("no-args stderr = %q, want '--' in usage", errOut)
	}
}
