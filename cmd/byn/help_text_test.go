package main

import (
	"strings"
	"testing"
)

func TestHelpFor_AllCanonicalCommandsRegistered(t *testing.T) {
	canonical := []string{
		"init", "unlock", "lock", "put", "get", "list", "delete", "exec",
		"rename", "edit", "daemon", "status", "version", "help", "vault",
		"project", "env", "import", "export", "setup", "migrate",
	}
	for _, name := range canonical {
		if got := helpFor(name); got == "" {
			t.Errorf("helpFor(%q) returned empty — missing entry?", name)
		}
	}
}

func TestHelpFor_AliasesRoute(t *testing.T) {
	aliases := map[string]string{
		"cat":  "get",
		"ls":   "list",
		"rm":   "delete",
		"mv":   "rename",
		"view": "edit",
	}
	for alias, canonical := range aliases {
		got := helpFor(alias)
		want := helpFor(canonical)
		if got == "" || got != want {
			t.Errorf("alias %q routed wrong: got len=%d, want canonical len=%d",
				alias, len(got), len(want))
		}
	}
}

func TestHelpFor_UnknownReturnsEmpty(t *testing.T) {
	if got := helpFor("nonexistent-command"); got != "" {
		t.Fatalf("expected empty, got %q", got[:20])
	}
}

func TestCommandHelp_HasRequiredSections(t *testing.T) {
	// AWS-CLI convention: NAME / SYNOPSIS / DESCRIPTION / EXIT STATUS / SEE ALSO
	for name, blob := range commandHelp {
		for _, section := range []string{"NAME", "SYNOPSIS", "DESCRIPTION"} {
			if !strings.Contains(blob, section) {
				t.Errorf("%q help missing section %q", name, section)
			}
		}
	}
}
