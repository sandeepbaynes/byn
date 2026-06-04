package main

import (
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
			if sc != tc.wantSC {
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
