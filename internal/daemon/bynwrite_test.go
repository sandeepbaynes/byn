package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestBynFileContent(t *testing.T) {
	c := bynFileContent(ipc.Scope{Vault: "v", Project: "p", Env: "dev"}, []string{"A", "B"})
	for _, want := range []string{
		"[scope]", `vault   = "v"`, `project = "p"`, `env     = "dev"`,
		"[exec]", `env = ["A", "B"]`,
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("missing %q in:\n%s", want, c)
		}
	}
	// No vars ⇒ no [exec] table; empty scope fields are omitted.
	c2 := bynFileContent(ipc.Scope{Project: "p"}, nil)
	if strings.Contains(c2, "[exec]") {
		t.Fatalf("no vars should mean no [exec]:\n%s", c2)
	}
	if strings.Contains(c2, "vault") {
		t.Fatalf("empty vault should be omitted:\n%s", c2)
	}
}

func TestBynWrite_WritesFileWithoutTrust(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, EnvVars: []string{"API_KEY"}}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write: %v", err)
	}
	want := filepath.Join(dir, ".byn")
	if resp.Path != want {
		t.Fatalf("path = %q, want %q", resp.Path, want)
	}
	if resp.Trusted {
		t.Fatal("trusted should be false when Trust is unset")
	}
	body, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("read written .byn: %v", err)
	}
	if !strings.Contains(string(body), `project = "svc"`) || !strings.Contains(string(body), `env = ["API_KEY"]`) {
		t.Fatalf("written content unexpected:\n%s", body)
	}
	if bynTrusted(t, d, want, string(body)) {
		t.Fatal("file should NOT be trusted without Trust")
	}
}

func TestBynWrite_TrustNow(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, EnvVars: []string{"API_KEY"}, Trust: true, Password: pw}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write+trust: %v", err)
	}
	if !resp.Trusted {
		t.Fatal("trusted should be true after Trust=true")
	}
	body, _ := os.ReadFile(resp.Path)
	if !bynTrusted(t, d, resp.Path, string(body)) {
		t.Fatal("file should be trusted after a trust-now write")
	}
}

func TestBynWrite_TrustWithoutPassword_Denied(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	dir := t.TempDir()

	err := c.Call(ipc.OpBynWrite,
		ipc.BynWriteReq{Dir: dir, Scope: ipc.Scope{Project: "svc"}, Trust: true},
		&ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
	// The password is checked BEFORE the write, so nothing should land.
	if _, statErr := os.Stat(filepath.Join(dir, ".byn")); statErr == nil {
		t.Fatal(".byn was written despite the denied trust")
	}
}

func TestBynWrite_NotADirectory(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	f := writeByn(t, "x") // a file, not a directory

	err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{Dir: f}, &ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}

func TestWithResolvedActionTargets(t *testing.T) {
	base := "/home/u/proj"
	cases := []struct {
		name    string
		in      string
		want    []string
		comment string
	}{
		{
			name: "relative target gains an absolute twin",
			in:   "./build.sh",
			want: []string{"./build.sh", "/home/u/proj/build.sh"},
		},
		{
			name: "placeholders are preserved on the resolved copy",
			in:   "./app.sh {{args}}",
			want: []string{"./app.sh {{args}}", "/home/u/proj/app.sh {{args}}"},
		},
		{
			name: "nested relative path",
			in:   ".venv/bin/python {{args}}",
			want: []string{".venv/bin/python {{args}}", "/home/u/proj/.venv/bin/python {{args}}"},
		},
		{
			name:    "bare command is left alone",
			in:      "pytest {{args}}",
			want:    []string{"pytest {{args}}"},
			comment: "resolved through PATH by the CLI, argv[0] is not rewritten",
		},
		{
			name: "absolute target is already canonical",
			in:   "/usr/bin/make build",
			want: []string{"/usr/bin/make build"},
		},
		{
			name: "parent-relative path",
			in:   "../tools/gen.sh",
			want: []string{"../tools/gen.sh", "/home/u/tools/gen.sh"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withResolvedActionTargets([]string{tc.in}, base)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// A pattern that is already absolute must not be duplicated, and an input that
// resolves onto an existing entry must collapse rather than appear twice.
func TestWithResolvedActionTargets_NoDuplicates(t *testing.T) {
	got := withResolvedActionTargets(
		[]string{"./build.sh", "/home/u/proj/build.sh"}, "/home/u/proj")
	want := []string{"./build.sh", "/home/u/proj/build.sh"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q, want %q", i, got[i], want[i])
		}
	}
}

// The record's path is symlink-resolved but `byn exec` only absolutizes argv[0]
// — it does not resolve symlinks. Where a project sits under a symlink (macOS
// puts temp dirs under /var -> /private/var) the two spellings differ, and a
// twin for only one of them means a relative action never matches.
func TestWithResolvedActionTargets_BothPathSpellings(t *testing.T) {
	got := withResolvedActionTargets([]string{"./run.sh"},
		"/private/var/p", "/var/p")
	want := []string{"./run.sh", "/private/var/p/run.sh", "/var/p/run.sh"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q, want %q", i, got[i], want[i])
		}
	}
	// Identical spellings must not produce a duplicate.
	if g := withResolvedActionTargets([]string{"./run.sh"}, "/p", "/p"); len(g) != 2 {
		t.Errorf("duplicate twin for identical dirs: %q", g)
	}
}
