//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An ad hoc request, driven end to end: asked from a directory with no .byn,
// queued with the whole question on the card, approved with the vault's
// password, and run — receiving exactly the names approved and nothing else.
func TestE2E_Adhoc_AskApproveRunWithExactlyTheNamedVariables(t *testing.T) {
	s, _, _ := bootstrapExecFetch(t, "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\n")
	for name, value := range map[string]string{"DB_URL": "postgres://x", "API_KEY": "k-1", "EXTRA": "never"} {
		if _, se, code := s.run(value, "--project", "alpha", "put", name); code != 0 {
			t.Fatalf("put %s: code=%d stderr=%q", name, code, se)
		}
	}
	// Somewhere with no .byn at all.
	dir := filepath.Join(s.dir, "elsewhere")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	ask := []string{"exec", "--project", "alpha", "--var", "DB_URL", "--var", "API_KEY", "--var", "NOT_YET",
		"--reason", "one-off backfill", "--", "/usr/bin/env"}
	if so, se, code := s.runInDir(dir, "", nil, ask...); code != 75 {
		t.Fatalf("ad hoc without a grant: code=%d, want 75\nstdout=%q\nstderr=%q", code, so, se)
	} else if !strings.Contains(se, "approval") || !strings.Contains(se, "DB_URL") {
		t.Fatalf("the pause must name the request and what it asks for: %q", se)
	}

	var card struct {
		ID      string   `json:"id"`
		Kind    string   `json:"kind"`
		Vault   string   `json:"vault"`
		Project string   `json:"project"`
		Env     string   `json:"env"`
		Gets    []string `json:"gets"`
		Subject string   `json:"subject"`
		Beside  string   `json:"beside"`
	}
	stdout, se, code := s.run("", "approve", "--json")
	if code != 0 {
		t.Fatalf("approve --json: code=%d stderr=%q", code, se)
	}
	var cards []json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &cards); err != nil || len(cards) != 1 {
		t.Fatalf("want one card, got %v: %s", err, stdout)
	}
	if err := json.Unmarshal(cards[0], &card); err != nil {
		t.Fatal(err)
	}
	if card.Kind != "adhoc" || card.Vault != "default" || card.Project != "alpha" || card.Env != "default" ||
		strings.Join(card.Gets, ",") != "API_KEY,DB_URL,NOT_YET" || card.Beside != "" {
		t.Fatalf("card = %+v — the whole question must be on it", card)
	}
	if !strings.HasSuffix(card.Subject, "elsewhere") {
		t.Fatalf("subject = %q, want the directory asked from", card.Subject)
	}
	// The human-readable card says the same.
	listed, _, _ := s.run("", "approve")
	for _, want := range []string{"scope", "project alpha", "gets", "API_KEY, DB_URL, NOT_YET", "ad hoc", "lasts", "1h"} {
		if !strings.Contains(listed, want) {
			t.Errorf("byn approve output lacks %q:\n%s", want, listed)
		}
	}

	if _, se, code := s.run(execfetchPW+"\n", "approve", "--password-stdin", card.ID); code != 0 {
		t.Fatalf("approve: code=%d stderr=%q", code, se)
	}
	so, se, code := s.runInDir(dir, "", nil, ask...)
	if code != 0 {
		t.Fatalf("approved ad hoc run: code=%d stderr=%q", code, se)
	}
	if !strings.Contains(so, "DB_URL=postgres://x") || !strings.Contains(so, "API_KEY=k-1") {
		t.Errorf("child env lacks the approved values:\n%s", so)
	}
	if strings.Contains(so, "EXTRA=") {
		t.Errorf("EXTRA reached the child — the grant covers only the names on the card:\n%s", so)
	}
	if !strings.Contains(se, "NOT_YET") {
		t.Errorf("a name with no value must be reported, not dropped: %q", se)
	}

	// One more name is a new question.
	more := append(append([]string{}, ask[:len(ask)-2]...), "--var", "EXTRA", "--", "/usr/bin/env")
	if _, _, code := s.runInDir(dir, "", nil, more...); code != 75 {
		t.Errorf("adding a name ran on the old grant: code=%d", code)
	}
}

// Beside a trusted .byn, a scope that contradicts the file is refused with
// the way out named; with --var it is an ad hoc request, flagged on the card.
func TestE2E_Adhoc_ScopeClashRefusesThenAsksAdhoc(t *testing.T) {
	s, projDir, dotPath := bootstrapExecFetch(t, "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\nactions = [\"/usr/bin/env\"]\n")
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil, "trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	if _, _, code := s.run("", "project", "create", "beta"); code != 0 {
		t.Fatal("project create beta")
	}

	_, se, code := s.runInDir(projDir, "", nil, "exec", "--project", "beta", "--", "/usr/bin/env")
	if code == 0 || code == 75 || !strings.Contains(se, "pins project alpha, not beta") ||
		!strings.Contains(se, "--var NAME") || !strings.Contains(se, "--no-discovery") {
		t.Fatalf("scope clash: code=%d stderr=%q — must refuse and name both ways out", code, se)
	}
	// The second way out: with the .byn set aside, the same command is an
	// ordinary no-.byn run, gated by the vault password rather than refused.
	_, se, code = s.runInDir(projDir, "", nil, "exec", "--no-discovery", "--project", "beta", "--", "/usr/bin/env")
	if code == 0 || code == 75 || strings.Contains(se, "pins project") ||
		(!strings.Contains(se, "auth") && !strings.Contains(se, "password")) {
		t.Fatalf("--no-discovery: code=%d stderr=%q — must ask for the password, not refuse on the .byn", code, se)
	}

	if _, se, code := s.runInDir(projDir, "", nil, "exec", "--project", "beta", "--var", "DB_URL",
		"--", "/usr/bin/env"); code != 75 {
		t.Fatalf("with --var: code=%d stderr=%q, want 75", code, se)
	}
	entries := listApprovalsJSON(t, s)
	if len(entries) != 1 || entries[0].Vault != "default" {
		t.Fatalf("want one pending request, got %+v", entries)
	}
	listed, _, _ := s.runInDir(projDir, "", nil, "approve")
	if !strings.Contains(listed, "beside") || !strings.Contains(listed, "project beta") {
		t.Errorf("the card must flag the .byn it steps around and name the scope:\n%s", listed)
	}
}
