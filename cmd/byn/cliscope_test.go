package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestCliScope_String_Defaults(t *testing.T) {
	cases := []struct {
		name string
		s    cliScope
		want string
	}{
		{"all empty", cliScope{}, "default/default/default"},
		{"vault only", cliScope{Vault: "acme"}, "acme/default/default"},
		{"all set", cliScope{Vault: "v", Project: "p", Env: "e"}, "v/p/e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.String(); got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCliScope_ToIPC(t *testing.T) {
	s := cliScope{Vault: "v", Project: "p", Env: "e"}
	ipc := s.ToIPC()
	if ipc.Vault != "v" || ipc.Project != "p" || ipc.Env != "e" {
		t.Fatalf("ToIPC = %+v", ipc)
	}
	// Empty fields stay empty.
	empty := (cliScope{}).ToIPC()
	if empty.Vault != "" || empty.Project != "" || empty.Env != "" {
		t.Fatalf("empty ToIPC = %+v", empty)
	}
}

func TestSplitFlag(t *testing.T) {
	cases := []struct {
		in    string
		name  string
		value string
		has   bool
	}{
		{"--vault", "--vault", "", false},
		{"--vault=acme", "--vault", "acme", true},
		{"--vault=a=b", "--vault", "a=b", true},
		{"notaflag", "", "", false},
		{"-v", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, v, h := splitFlag(tc.in)
			if n != tc.name || v != tc.value || h != tc.has {
				t.Fatalf("got (%q,%q,%v), want (%q,%q,%v)", n, v, h, tc.name, tc.value, tc.has)
			}
		})
	}
}

func TestSetScopeField(t *testing.T) {
	var sc cliScope
	if err := setScopeField(&sc, "--vault", "v1"); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// Same value is fine (idempotent).
	if err := setScopeField(&sc, "--vault", "v1"); err != nil {
		t.Fatalf("idempotent set: %v", err)
	}
	// Different value errors.
	if err := setScopeField(&sc, "--vault", "v2"); err == nil {
		t.Fatal("expected err on conflicting --vault")
	}
	if err := setScopeField(&sc, "--project", "p"); err != nil {
		t.Fatalf("set project: %v", err)
	}
	if err := setScopeField(&sc, "--project", "p2"); err == nil {
		t.Fatal("expected err on conflicting --project")
	}
	if err := setScopeField(&sc, "--env", "e"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	if err := setScopeField(&sc, "--env", "e2"); err == nil {
		t.Fatal("expected err on conflicting --env")
	}
	// Unknown flag is a no-op (default case).
	if err := setScopeField(&sc, "--unknown", "x"); err != nil {
		t.Fatalf("unknown flag should be no-op: %v", err)
	}
}

func TestStripFlagToken(t *testing.T) {
	in := []string{"--json", "exec", "--json", "--", "cmd"}
	out := stripFlagToken(in, "--json")
	if len(out) != 3 || out[0] != "exec" || out[1] != "--" || out[2] != "cmd" {
		t.Fatalf("stripFlagToken = %v", out)
	}
	// No match leaves the slice unchanged.
	out2 := stripFlagToken([]string{"a", "b"}, "--zz")
	if len(out2) != 2 || out2[0] != "a" || out2[1] != "b" {
		t.Fatalf("no-match = %v", out2)
	}
}

func TestJsonModeFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"present", []string{"list", "--json"}, true},
		{"explicit true", []string{"--json=true"}, true},
		{"absent", []string{"list"}, false},
		{"after dash", []string{"exec", "--", "--json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonModeFromArgs(tc.args); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNoDiscoveryFromArgs(t *testing.T) {
	if !noDiscoveryFromArgs([]string{"list", "--no-discovery"}) {
		t.Fatal("expected true")
	}
	if noDiscoveryFromArgs([]string{"list"}) {
		t.Fatal("expected false")
	}
	if noDiscoveryFromArgs([]string{"exec", "--", "--no-discovery"}) {
		t.Fatal("expected false after --")
	}
}

func TestPreParseGlobals_Forms(t *testing.T) {
	// Clear env to avoid BYN_VAULT etc bleeding in.
	t.Setenv(envFallbackKeys.Vault, "")
	t.Setenv(envFallbackKeys.Project, "")
	t.Setenv(envFallbackKeys.Env, "")

	cases := []struct {
		name    string
		in      []string
		wantSC  cliScope
		wantOut []string
	}{
		{"two-token form", []string{"--vault", "acme", "list"}, cliScope{Vault: "acme"}, []string{"list"}},
		{"equals form", []string{"--vault=acme", "list"}, cliScope{Vault: "acme"}, []string{"list"}},
		{"all three", []string{"--vault=v", "--project=p", "--env=e", "list"}, cliScope{Vault: "v", Project: "p", Env: "e"}, []string{"list"}},
		{"after dash untouched", []string{"exec", "--", "--vault", "x"}, cliScope{}, []string{"exec", "--", "--vault", "x"}},
		{"interleaved", []string{"list", "--vault", "v"}, cliScope{Vault: "v"}, []string{"list"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, out, err := preParseGlobals(tc.in)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !reflect.DeepEqual(sc, tc.wantSC) {
				t.Fatalf("scope = %+v, want %+v", sc, tc.wantSC)
			}
			if len(out) != len(tc.wantOut) {
				t.Fatalf("out = %v, want %v", out, tc.wantOut)
			}
			for i, v := range out {
				if v != tc.wantOut[i] {
					t.Fatalf("out[%d] = %q, want %q", i, v, tc.wantOut[i])
				}
			}
		})
	}
}

func TestPreParseGlobals_EnvFallback(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "envv")
	t.Setenv(envFallbackKeys.Project, "envp")
	t.Setenv(envFallbackKeys.Env, "enve")
	sc, _, err := preParseGlobals([]string{"list"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if sc.Vault != "envv" || sc.Project != "envp" || sc.Env != "enve" {
		t.Fatalf("env fallback failed: %+v", sc)
	}
	// CLI flag wins.
	sc2, _, err := preParseGlobals([]string{"--vault=cliv", "list"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if sc2.Vault != "cliv" {
		t.Fatalf("flag should win: %+v", sc2)
	}
}

func TestPreParseGlobals_DuplicateConflict(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "")
	_, _, err := preParseGlobals([]string{"--vault=a", "--vault=b"})
	if err == nil || !strings.Contains(err.Error(), "specified twice") {
		t.Fatalf("err = %v, want duplicate err", err)
	}
}

func TestPreParseGlobals_MissingValue(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "")
	_, _, err := preParseGlobals([]string{"--vault"})
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("err = %v, want missing-value", err)
	}
}

// ── exec passthrough boundary tests (Part A.2) ──────────────────────────────

// TestExecPassthroughBoundary_AliasBoundary: when exec is followed by an alias
// name, the boundary index is the slot AFTER the alias name (first opaque arg).
func TestExecPassthroughBoundary_AliasBoundary(t *testing.T) {
	// ["exec", "name", "--vault", "prod"] → boundary at index 2 (after "name")
	args := []string{"exec", "name", "--vault", "prod"}
	got := execPassthroughBoundary(args)
	if got != 2 {
		t.Errorf("boundary = %d, want 2", got)
	}
}

// TestExecPassthroughBoundary_DirectForm: exec followed by "--" → boundary at
// the "--" itself.
func TestExecPassthroughBoundary_DirectForm(t *testing.T) {
	args := []string{"exec", "--", "cmd", "--vault", "prod"}
	got := execPassthroughBoundary(args)
	if got != 1 {
		t.Errorf("boundary = %d, want 1 (index of --)", got)
	}
}

// TestExecPassthroughBoundary_GlobalsBeforeExec: exec after globals → boundary
// at index of first non-flag after exec.
func TestExecPassthroughBoundary_GlobalsBeforeExec(t *testing.T) {
	// ["--vault", "x", "exec", "name", "--flag"] → exec at 2, alias "name" at 3, boundary at 4.
	args := []string{"--vault", "x", "exec", "name", "--flag"}
	got := execPassthroughBoundary(args)
	if got != 4 {
		t.Errorf("boundary = %d, want 4", got)
	}
}

// TestExecPassthroughBoundary_NoExec: no exec subcommand → returns -1.
func TestExecPassthroughBoundary_NoExec(t *testing.T) {
	args := []string{"list", "--vault", "x"}
	got := execPassthroughBoundary(args)
	if got != -1 {
		t.Errorf("boundary = %d, want -1 (no exec)", got)
	}
}

// TestPreParseGlobals_ExecAliasPassthrough: `byn exec name --vault prod` must
// pass --vault prod through untouched (not consume it as a global flag), while
// `byn --vault x exec name` must consume the pre-exec global flag normally.
func TestPreParseGlobals_ExecAliasPassthrough(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "")
	t.Setenv(envFallbackKeys.Project, "")
	t.Setenv(envFallbackKeys.Env, "")

	// Case 1: --vault after alias name must NOT be consumed.
	sc, out, err := preParseGlobals([]string{"exec", "deploy", "--vault", "prod"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if sc.Vault != "" {
		t.Errorf("scope.Vault = %q, want empty (passthrough should not set it)", sc.Vault)
	}
	// The entire suffix ["deploy", "--vault", "prod"] must appear in out.
	wantOut := []string{"exec", "deploy", "--vault", "prod"}
	if !reflect.DeepEqual(out, wantOut) {
		t.Errorf("out = %v, want %v", out, wantOut)
	}

	// Case 2: --vault BEFORE exec must be consumed normally.
	sc2, out2, err2 := preParseGlobals([]string{"--vault", "x", "exec", "deploy"})
	if err2 != nil {
		t.Fatalf("err: %v", err2)
	}
	if sc2.Vault != "x" {
		t.Errorf("scope.Vault = %q, want x", sc2.Vault)
	}
	wantOut2 := []string{"exec", "deploy"}
	if !reflect.DeepEqual(out2, wantOut2) {
		t.Errorf("out = %v, want %v", out2, wantOut2)
	}
}

// TestJsonModeFromArgs_ExecAliasPassthrough: --json after the alias name must
// NOT flip agent mode.
func TestJsonModeFromArgs_ExecAliasPassthrough(t *testing.T) {
	// --json after alias name: opaque → must not flip agent mode.
	if jsonModeFromArgs([]string{"exec", "alias", "--json"}) {
		t.Error("--json after exec alias name should NOT flip agent mode")
	}
	// --json before exec: must flip agent mode.
	if !jsonModeFromArgs([]string{"--json", "exec", "alias"}) {
		t.Error("--json before exec should flip agent mode")
	}
	// --json with direct form: after "--" is already blocked by original check.
	if jsonModeFromArgs([]string{"exec", "--", "--json"}) {
		t.Error("--json after -- should NOT flip agent mode")
	}
}

// TestWantsHelp_ExecAliasPassthrough: --help / -h after the alias name must
// NOT trigger byn's own help display.
func TestWantsHelp_ExecAliasPassthrough(t *testing.T) {
	// --help after alias name: opaque → must NOT trigger byn help.
	// This is tested via wantsHelp with the slice trimmed at the alias boundary
	// (as main.go does it): wantsHelp(rest[:aliasIdx]) where rest = ["myalias", "--help"].
	// When trimmed to rest[:0] = [], wantsHelp must return false.
	if wantsHelp([]string{}) {
		t.Error("wantsHelp(empty) should be false")
	}
	// wantsHelp on pre-alias slice: only items before the alias — no --help there.
	if wantsHelp([]string{"myalias"}[:0]) { // empty slice (all before the alias)
		t.Error("no help flags before alias: wantsHelp should be false")
	}
	// Confirm wantsHelp still works for normal cases.
	if !wantsHelp([]string{"--help"}) {
		t.Error("wantsHelp([--help]) should be true")
	}
	if !wantsHelp([]string{"-h"}) {
		t.Error("wantsHelp([-h]) should be true")
	}
	if !wantsHelp([]string{"help"}) {
		t.Error("wantsHelp([help]) should be true (single token)")
	}
}

// TestPreParseGlobals_ExecNoAliasName: `byn exec` or `byn exec --help` (no
// alias name) — no passthrough boundary, pre-parser works normally.
func TestPreParseGlobals_ExecNoAliasName(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "")
	t.Setenv(envFallbackKeys.Project, "")
	t.Setenv(envFallbackKeys.Env, "")

	// byn exec (no further args): no boundary.
	sc, out, err := preParseGlobals([]string{"exec"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if sc.Vault != "" {
		t.Errorf("scope.Vault = %q, want empty", sc.Vault)
	}
	if !reflect.DeepEqual(out, []string{"exec"}) {
		t.Errorf("out = %v, want [exec]", out)
	}
}

// TestPreParseGlobals_DirectFormUnchanged: `byn exec -- cmd` (direct form)
// must pass everything after "--" through unchanged (existing behaviour).
func TestPreParseGlobals_DirectFormUnchanged(t *testing.T) {
	t.Setenv(envFallbackKeys.Vault, "")
	t.Setenv(envFallbackKeys.Project, "")
	t.Setenv(envFallbackKeys.Env, "")

	sc, out, err := preParseGlobals([]string{"exec", "--", "cmd", "--vault", "x"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if sc.Vault != "" {
		t.Errorf("scope.Vault = %q, want empty", sc.Vault)
	}
	want := []string{"exec", "--", "cmd", "--vault", "x"}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("out = %v, want %v", out, want)
	}
}
