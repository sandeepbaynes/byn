package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// The [exec] env allowlist parses from .byn as either a bare string or a list.
// ExecEnv was removed from cliScope (it's now daemon-side only via exec.fetch);
// test bynfile.Parse directly so the parsing contract is still exercised.
func TestBynfileExecEnvAllowlist(t *testing.T) {
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
			parsed, err := bynfile.Parse([]byte(tc.body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := []string(parsed.Exec.Env)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Exec.Env = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestRenderAllowlistNotes_Wildcard checks that the "permits ALL" warning
// is printed when the daemon signals Wildcard=true.
func TestRenderAllowlistNotes_Wildcard(t *testing.T) {
	resp := ipc.ExecFetchResp{
		Values:   []ipc.ExecFetchValue{{Name: "A", Value: []byte("1")}, {Name: "B", Value: []byte("2")}},
		Wildcard: true,
	}
	sourcePath := "/proj/.byn"
	out := captureStderr(t, func() {
		renderAllowlistNotes(resp, sourcePath)
	})
	if !strings.Contains(out, "permits ALL") {
		t.Errorf("expected 'permits ALL' in stderr, got: %q", out)
	}
	if !strings.Contains(out, sourcePath) {
		t.Errorf("expected path %q in stderr, got: %q", sourcePath, out)
	}
	if !strings.Contains(out, "2") { // count of values
		t.Errorf("expected value count in stderr, got: %q", out)
	}
}

// TestRenderAllowlistNotes_NoneDeclared checks that the "declares no [exec]
// env vars" note is printed when the daemon signals NoneDeclared=true.
func TestRenderAllowlistNotes_NoneDeclared(t *testing.T) {
	resp := ipc.ExecFetchResp{
		NoneDeclared: true,
	}
	sourcePath := "/proj/.byn"
	out := captureStderr(t, func() {
		renderAllowlistNotes(resp, sourcePath)
	})
	if !strings.Contains(out, "declares no [exec] env vars") {
		t.Errorf("expected note in stderr, got: %q", out)
	}
	if !strings.Contains(out, sourcePath) {
		t.Errorf("expected path %q in stderr, got: %q", sourcePath, out)
	}
}

// TestRenderAllowlistNotes_AdHoc checks that no note is printed when
// sourcePath is empty (ad-hoc exec with no .byn).
func TestRenderAllowlistNotes_AdHoc(t *testing.T) {
	resp := ipc.ExecFetchResp{
		Wildcard:     true,
		NoneDeclared: true,
	}
	out := captureStderr(t, func() {
		renderAllowlistNotes(resp, "")
	})
	if out != "" {
		t.Errorf("expected no output for ad-hoc exec, got: %q", out)
	}
}
