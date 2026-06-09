package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// The [exec] env allowlist parses from .byn as either a bare string or a list.
func TestDiscoverScope_ExecEnvAllowlist(t *testing.T) {
	t.Setenv("BYN_NO_DISCOVERY", "")
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"wildcard string", "[scope]\nvault=\"v\"\n[exec]\nenv = \"*\"\n", []string{"*"}},
		{"wildcard list", "[scope]\nvault=\"v\"\n[exec]\nenv = [\"*\"]\n", []string{"*"}},
		{"explicit list", "[scope]\nvault=\"v\"\n[exec]\nenv = [\"A\", \"B\"]\n", []string{"A", "B"}},
		{"empty list", "[scope]\nvault=\"v\"\n[exec]\nenv = []\n", []string{}},
		{"no exec table", "[scope]\nvault=\"v\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := t.TempDir()
			if err := os.WriteFile(filepath.Join(start, ".byn"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			sc, _, err := discoverScope(start, t.TempDir(), t.TempDir(), false)
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			if !reflect.DeepEqual(sc.ExecEnv, tc.want) {
				t.Fatalf("ExecEnv = %#v, want %#v", sc.ExecEnv, tc.want)
			}
		})
	}
}

func TestFilterExecEnv(t *testing.T) {
	all := []ipc.SecretMeta{{Name: "A"}, {Name: "B"}, {Name: "C"}}
	names := func(ms []ipc.SecretMeta) []string {
		out := make([]string, len(ms))
		for i, m := range ms {
			out[i] = m.Name
		}
		return out
	}
	cases := []struct {
		name  string
		scope cliScope
		want  []string
	}{
		{"no .byn injects all", cliScope{}, []string{"A", "B", "C"}},
		{"wildcard injects all", cliScope{SourcePath: "/p/.byn", ExecEnv: []string{"*"}}, []string{"A", "B", "C"}},
		{"list injects subset", cliScope{SourcePath: "/p/.byn", ExecEnv: []string{"A", "C"}}, []string{"A", "C"}},
		{"empty injects none", cliScope{SourcePath: "/p/.byn", ExecEnv: []string{}}, []string{}},
		{"absent injects none", cliScope{SourcePath: "/p/.byn"}, []string{}},
		{"unknown names ignored", cliScope{SourcePath: "/p/.byn", ExecEnv: []string{"A", "NOPE"}}, []string{"A"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := names(filterExecEnv(all, tc.scope))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
