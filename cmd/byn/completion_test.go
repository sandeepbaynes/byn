package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// dispatchAliases are second spellings of a command. They dispatch, but are
// deliberately NOT offered for completion: they exist for muscle memory, not
// discovery, and listing both spellings doubles what a person reads to find out
// what byn can do.
var dispatchAliases = map[string]string{
	"cat": "get", "ls": "list", "rm": "delete", "mv": "rename",
	"view": "edit", "ui": "web", "password": "passwd",
}

// dispatchNotCommands are case values that are not commands a person types as a
// first word: flag spellings of help/version, and the hidden completion hook.
var dispatchNotCommands = map[string]bool{
	"--version": true, "-v": true, "--help": true, "-h": true,
	"__complete": true,
}

var caseString = regexp.MustCompile(`case ((?:"[a-z_.-][a-zA-Z0-9_.-]*"(?:, )?)+):`)
var quoted = regexp.MustCompile(`"([^"]+)"`)

// Every command byn DISPATCHES must be completable. This is the drift guard:
// adding a command to main.go without adding it here now fails the build,
// rather than leaving completion quietly describing an older CLI.
func TestCompletionCommands_CoverTheDispatchSwitch(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	offered := map[string]bool{}
	for _, c := range completionCommands {
		offered[c] = true
	}

	var missing []string
	for _, m := range caseString.FindAllStringSubmatch(string(src), -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			name := q[1]
			switch {
			case strings.Contains(name, "."): // vcs.revision & friends: not commands
				continue
			case dispatchNotCommands[name]:
				continue
			case dispatchAliases[name] != "":
				// An alias must at least point at a command that IS offered.
				if !offered[dispatchAliases[name]] {
					t.Errorf("alias %q maps to %q, which is not offered for completion",
						name, dispatchAliases[name])
				}
				continue
			case offered[name]:
				continue
			}
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("these dispatch to a command but are not offered by completion: %v\n"+
			"add them to completionCommands, or to dispatchAliases/dispatchNotCommands "+
			"if they are deliberately hidden", dedupe(missing))
	}
}

// The reverse: completion must not advertise a command that does not exist.
func TestCompletionCommands_AreAllReal(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range completionCommands {
		if !strings.Contains(string(src), `case "`+c+`"`) &&
			!strings.Contains(string(src), `"`+c+`",`) {
			t.Errorf("completion offers %q, which main.go does not dispatch", c)
		}
	}
}

// Flags are derived from SYNOPSIS rather than written down again. If that
// section's shape changes, completion silently empties out — so pin a few.
func TestFlagsForCommand_DerivesFromSynopsis(t *testing.T) {
	cases := map[string][]string{
		"doctor": {"--json", "--repair"},
		"kill":   {"--all"},
		"exec":   {"--dry-run", "--json", "--no-privsep", "--wait-approval"},
		"audit":  {"--lines", "--since", "--verify-ish-none"},
	}
	delete(cases, "audit") // covered below with its real flags
	for cmd, want := range cases {
		got := flagsForCommand(cmd)
		have := map[string]bool{}
		for _, f := range got {
			have[f] = true
		}
		for _, w := range want {
			if !have[w] {
				t.Errorf("%s: expected %s among %v", cmd, w, got)
			}
		}
	}
	// audit's flags live across its subcommands' synopsis lines.
	if got := flagsForCommand("audit"); len(got) < 5 {
		t.Errorf("audit: expected several flags, got %v", got)
	}
	// A command with no help blob must not panic or invent flags.
	if got := flagsForCommand("nonesuch"); got != nil {
		t.Errorf("unknown command produced %v", got)
	}
}

// A subcommand that has been renamed should be caught by its absence from the
// command's own documentation.
func TestCompletionSubcommands_AppearInTheirHelp(t *testing.T) {
	for cmd, subs := range completionSubcommands {
		help, ok := commandHelp[cmd]
		if !ok {
			continue // some commands document subcommands elsewhere
		}
		for _, sub := range subs {
			if !strings.Contains(help, sub) {
				t.Errorf("`byn %s %s` is offered, but %q does not appear in its help — renamed?",
					cmd, sub, sub)
			}
		}
	}
}

func TestCompleteWords_FirstWordOffersCommands(t *testing.T) {
	got := completeWords([]string{""})
	if len(got) < 20 {
		t.Fatalf("expected the full command list, got %d", len(got))
	}
	if got[0] != "approve" {
		t.Errorf("expected sorted output, got %v", got[:3])
	}
}

func TestCompleteWords_FiltersByPrefix(t *testing.T) {
	got := completeWords([]string{"doc"})
	if len(got) != 1 || got[0] != "doctor" {
		t.Fatalf(`"doc" completed to %v, want [doctor]`, got)
	}
}

// The trailing empty word is what separates a half-typed command from a
// finished one. Without it both arrive as ["doctor"] and one must be wrong.
func TestCompleteWords_EmptyTrailingWordMeansOptionsNotCommands(t *testing.T) {
	halfTyped := completeWords([]string{"doctor"})
	finished := completeWords([]string{"doctor", ""})
	if len(halfTyped) != 1 || halfTyped[0] != "doctor" {
		t.Errorf(`"byn doctor<TAB>" should complete the command, got %v`, halfTyped)
	}
	if len(finished) == 0 || !strings.HasPrefix(finished[0], "-") {
		t.Errorf(`"byn doctor <TAB>" should offer options, got %v`, finished)
	}
}

func TestCompleteWords_DashOffersOnlyFlags(t *testing.T) {
	got := completeWords([]string{"audit", "--"})
	if len(got) == 0 {
		t.Fatal("no flags offered")
	}
	for _, c := range got {
		if !strings.HasPrefix(c, "--") {
			t.Errorf("a dash prefix must offer flags only, got %q", c)
		}
	}
}

func TestCompleteWords_SubcommandsBeforeFlags(t *testing.T) {
	got := completeWords([]string{"audit", ""})
	for _, c := range got {
		if strings.HasPrefix(c, "-") {
			t.Errorf("bare TAB after a command with subcommands should not list flags, got %v", got)
			break
		}
	}
	if len(got) != len(completionSubcommands["audit"]) {
		t.Errorf("got %v, want the audit subcommands", got)
	}
}

// Everything after `--` belongs to the child program. byn completing there
// would offer its own flags for somebody else's command.
func TestCompleteWords_StopsAtTheExecBoundary(t *testing.T) {
	if got := completeWords([]string{"exec", "--", ""}); len(got) != 0 {
		t.Errorf("completed past the -- boundary: %v", got)
	}
	if got := completeWords([]string{"exec", "--", "npm", ""}); len(got) != 0 {
		t.Errorf("completed a child's arguments: %v", got)
	}
}

func TestCompleteWords_AliasSharesItsCommandsFlags(t *testing.T) {
	direct := completeWords([]string{"list", "--"})
	alias := completeWords([]string{"ls", "--"})
	if len(alias) == 0 || strings.Join(direct, ",") != strings.Join(alias, ",") {
		t.Errorf("`ls` offered %v, `list` offered %v — an alias should share its flags", alias, direct)
	}
}

func TestExecAliases_ReadsTheLocalByn(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(".byn", []byte(
		"[scope]\nproject = \"p\"\nenv = \"dev\"\n\n[aliases]\ndev = \"npm run dev\"\ncheck = \"npm test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := execAliases()
	if len(got) != 2 || got[0] != "check" || got[1] != "dev" {
		t.Fatalf("got %v, want [check dev]", got)
	}
	// And it shows up through the real entry point.
	if c := completeWords([]string{"exec", "d"}); len(c) != 1 || c[0] != "dev" {
		t.Errorf("`byn exec d<TAB>` gave %v, want [dev]", c)
	}
}

// A completion must never surface an error: there is nowhere for it to go, and
// the shell renders whatever comes back as a candidate.
func TestExecAliases_MalformedBynIsSilent(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(".byn", []byte("this is not toml {{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := execAliases(); len(got) != 0 {
		t.Errorf("a malformed .byn produced candidates: %v", got)
	}
}

func TestCompletionScripts_CallBackIntoByn(t *testing.T) {
	for name, script := range map[string]string{
		"bash": completionBash, "zsh": completionZsh, "fish": completionFish,
	} {
		if !strings.Contains(script, "byn __complete") {
			t.Errorf("%s script does not call `byn __complete` — did the embed break?", name)
		}
		if len(script) < 100 {
			t.Errorf("%s script is suspiciously short (%d bytes)", name, len(script))
		}
	}
}

func TestRunCompletion_RejectsUnknownShell(t *testing.T) {
	if runCompletion([]string{"powershell"}, cliScope{}) == exitOK {
		t.Error("an unsupported shell must not exit 0")
	}
	if runCompletion(nil, cliScope{}) == exitOK {
		t.Error("no shell argument must not exit 0")
	}
}
