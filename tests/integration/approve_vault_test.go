//go:build integration

package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

// An approval is answered with the password of the vault it was raised in, and
// --vault is how an owner names that vault from anywhere. Driven end to end
// because the halves live in different processes: the CLI decides what is
// listed and which password to ask for, and the daemon decides whether that
// password counts.
func TestE2E_ApproveVault_ScopesTheQueueAndThePassword(t *testing.T) {
	bynContent := "[scope]\nproject = \"alpha\"\n[exec]\nenv = []\n"
	s, projDir, dotPath := bootstrapExecFetch(t, bynContent)
	if _, se, code := s.runInDir(projDir, execfetchPW+"\n", nil,
		"trust", "--password-stdin", dotPath); code != 0 {
		t.Fatalf("trust: code=%d stderr=%q", code, se)
	}
	const otherPW = "another-vaults-password-123"
	if _, se, code := s.run(otherPW+"\n", "--vault", "other", "init", "--password-stdin"); code != 0 {
		t.Fatalf("init other: code=%d stderr=%q", code, se)
	}

	// One request in the project's vault, and one against the other vault —
	// --vault placed after --reason, where it used to be dropped unseen. The
	// .byn is trusted for the default vault only, so the second is an ad hoc
	// request and must name what it wants.
	if _, _, code := s.runInDir(projDir, "", nil,
		"exec", "--reason", "default run", "--", "/usr/bin/env"); code == 0 {
		t.Fatal("unpinned exec should not run without approval")
	}
	if _, se, code := s.runInDir(projDir, "", nil,
		"exec", "--reason", "other run", "--vault", "other", "--var", "DB_URL", "--", "/usr/bin/env"); code != 75 {
		t.Fatalf("ad hoc in the other vault: code=%d stderr=%q, want 75", code, se)
	} else if strings.Contains(se, "unknown byn exec flag") {
		t.Fatalf("--vault after --reason was not taken as byn's: %q", se)
	}

	// Outside any project, with no vault named, everything is listed.
	byVault := map[string]string{}
	for _, e := range listApprovalsJSON(t, s) {
		byVault[e.Vault] = e.ID
		// The .byn pins project alpha — in the default vault. The request
		// in the other vault must not have borrowed it.
		if e.Vault == "other" && e.Project != "default" {
			t.Errorf("request in vault other is for project %q, want default (the .byn's alpha is not a project there)", e.Project)
		}
	}
	defaultID, otherID := byVault["default"], byVault["other"]
	if len(byVault) != 2 || defaultID == "" || otherID == "" {
		t.Fatalf("want one pending request per vault, got %v", byVault)
	}

	// --vault narrows the list to that vault.
	if got := listApprovalsJSON(t, s, "--vault", "other"); len(got) != 1 || got[0].ID != otherID {
		t.Fatalf("approve --vault other listed %+v, want only %s", got, otherID)
	}
	// Inside the project, its .byn picks the vault.
	stdout, se, code := s.runInDir(projDir, "", nil, "approve", "--json")
	if code != 0 {
		t.Fatalf("approve --json in project: code=%d stderr=%q", code, se)
	}
	var inProject []approvalEntryJSON
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &inProject); err != nil {
		t.Fatalf("approve --json: %v\n%s", err, stdout)
	}
	if len(inProject) != 1 || inProject[0].ID != defaultID {
		t.Fatalf("approve in the project listed %+v, want only %s", inProject, defaultID)
	}

	// One password on stdin cannot answer two vaults.
	if _, se, code := s.run(execfetchPW+"\n", "approve", "--all", "--password-stdin"); code == 0 ||
		!strings.Contains(se, "answers one vault") {
		t.Fatalf("--all across two vaults with --password-stdin: code=%d stderr=%q", code, se)
	}
	// A named vault that contradicts the id is refused before any password.
	if _, se, code := s.run(otherPW+"\n", "approve", "--vault", "other", "--password-stdin",
		defaultID); code == 0 || !strings.Contains(se, "waiting in vault default") {
		t.Fatalf("approve --vault other <default id>: code=%d stderr=%q", code, se)
	}

	// --all with --vault answers that vault's requests, with its password.
	if _, se, code := s.run(otherPW+"\n", "approve", "--all", "--vault", "other",
		"--password-stdin"); code != 0 {
		t.Fatalf("approve --all --vault other: code=%d stderr=%q", code, se)
	}
	if _, e := approvalByID(t, s, otherID); e.Status != "approved" {
		t.Fatalf("other's request is %q, want approved", e.Status)
	}
	if _, e := approvalByID(t, s, defaultID); e.Status != "pending" {
		t.Fatalf("default's request is %q — --vault other must not touch it", e.Status)
	}

	// And another vault's password never approves this one.
	if _, _, code := s.run(otherPW+"\n", "approve", "--password-stdin", defaultID); code == 0 {
		t.Fatal("the other vault's password approved a request in the default vault")
	}
	if _, e := approvalByID(t, s, defaultID); e.Status != "pending" {
		t.Fatalf("default's request is %q after a wrong password", e.Status)
	}
}
