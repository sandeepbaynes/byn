package main

// completion.go provides shell tab-completion: `byn <TAB>` lists commands,
// `byn <command> <TAB>` lists that command's subcommands and flags.
//
// The completions are DERIVED, not written down twice. A hand-maintained list
// of flags beside a hand-maintained parser is two things that must agree, and
// nothing fails when they stop agreeing — the completion simply starts lying
// about a CLI that has moved on. So:
//
//   - flags come from each command's own SYNOPSIS, which the repository already
//     requires updating whenever a flag changes;
//   - the command list is checked against main.go's dispatch switch by a test,
//     so adding a command without completing it fails the build;
//   - `byn exec <TAB>` reads the local .byn for its [aliases], because the
//     answer there depends on the directory rather than on the binary.
//
// The shell asks byn for candidates at each keystroke (see completions/*.sh),
// so nothing is baked into the installed script. That also means this path must
// stay FAST and must never touch the daemon: a tab press that blocks on a
// socket, or hangs when the daemon is down, is worse than no completion.

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sandeepbaynes/byn/internal/bynfile"
)

// completionSubcommands maps a command to the words that may follow it.
//
// Subcommands are listed rather than derived: they are a small, stable set, and
// the alternative is parsing prose. A test asserts every one of them appears in
// its command's help, so a renamed subcommand is caught.
var completionSubcommands = map[string][]string{
	"vault":   {"list", "delete", "rename", "init", "unlock", "lock", "passwd"},
	"project": {"create", "list", "delete", "rename"},
	"env":     {"create", "list", "delete", "rename", "clear"},
	"trust":   {"list", "diff"},
	"audit":   {"tail", "view", "verify", "reseal"},
	"daemon":  {"install", "uninstall"},
	"request": {"watch", "cancel"},
	"skill":   {"install", "show", "path"},
	"approve": {},
}

// completionCommands is every command `byn <TAB>` offers.
//
// Aliases are deliberately EXCLUDED. `ls`, `rm`, `mv`, `cat` and friends are
// there for muscle memory, not for discovery, and offering both spellings of
// nine commands doubles the list a person is reading to find out what byn can
// do. The test that checks this against the dispatch switch knows about them.
var completionCommands = []string{
	"approve", "audit", "completion", "config-auth", "daemon", "delete", "doctor",
	"edit", "env", "exec", "export", "get", "help", "import", "init", "kill",
	"list", "lock", "migrate", "passwd", "project", "ps", "put", "reload",
	"rename", "repair", "request", "restart", "runs", "setup", "skill", "start",
	"status", "stop", "trust", "uninstall", "unlock", "untrust", "vault",
	"version", "web",
}

// completionGlobalFlags work before or after the subcommand.
var completionGlobalFlags = []string{"--vault", "--project", "--env", "--json", "--no-discovery"}

// synopsisFlag finds long flags in a SYNOPSIS line.
//
// SYNOPSIS is used rather than OPTIONS because it is the one section that
// ENUMERATES: OPTIONS is prose with headings, so scanning it found a single
// flag for `byn exec` and none at all for `byn audit`, while picking up a
// `--project` that a sentence merely mentioned.
var synopsisFlag = regexp.MustCompile(`--[a-z][a-z0-9-]*`)

// flagsForCommand returns the flags named in a command's SYNOPSIS.
func flagsForCommand(cmd string) []string {
	help, ok := commandHelp[cmd]
	if !ok {
		return nil
	}
	syn := sectionOf(help, "SYNOPSIS")
	if syn == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range synopsisFlag.FindAllString(syn, -1) {
		if seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// sectionOf returns the body of a named help section, up to the next heading.
// Headings are unindented and upper-case, which is the whole grammar here.
func sectionOf(help, name string) string {
	lines := strings.Split(help, "\n")
	start := -1
	for i, l := range lines {
		if l == name {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	var b strings.Builder
	for _, l := range lines[start:] {
		if l != "" && l == strings.ToUpper(l) && !strings.HasPrefix(l, " ") {
			break
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// execAliases returns the [aliases] a nearby .byn declares, so `byn exec <TAB>`
// offers the names that actually work HERE.
//
// It walks up from the working directory the way scope discovery does, and is
// entirely best-effort: a missing, unreadable or malformed .byn yields nothing.
// A completion must never report an error — there is nowhere for it to go, and
// the shell would render it as a candidate.
func execAliases() []string {
	dir, err := os.Getwd()
	if err != nil {
		return nil
	}
	for i := 0; i < 40; i++ {
		body, rerr := os.ReadFile(filepath.Join(dir, ".byn")) //nolint:gosec // a .byn in the caller's own tree
		if rerr == nil {
			f, perr := bynfile.Parse(body)
			if perr != nil {
				return nil
			}
			out := make([]string, 0, len(f.Aliases))
			for name := range f.Aliases {
				out = append(out, name)
			}
			sort.Strings(out)
			return out
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
	return nil
}

// completeWords returns the candidates for a partially typed command line.
//
// words is everything after "byn", with the word being completed LAST — always
// present, and empty when the cursor sits on a fresh word. That trailing empty
// is what separates `byn doc<TAB>` from `byn doctor <TAB>`; without it the two
// arrive identically and one of them must be answered wrongly.
func completeWords(words []string) []string {
	if len(words) == 0 {
		words = []string{""}
	}
	cur := words[len(words)-1]
	prior := words[:len(words)-1]

	// Nothing but the current word: the command itself.
	if len(prior) == 0 {
		if strings.HasPrefix(cur, "-") {
			return filterPrefix(completionGlobalFlags, cur)
		}
		return filterPrefix(completionCommands, cur)
	}

	cmd := canonicalCommand(prior[0])

	// After `--` the rest belongs to the child program, not to byn.
	for _, w := range prior {
		if w == "--" {
			return nil
		}
	}

	flags := append(flagsForCommand(cmd), completionGlobalFlags...)

	// Typing a dash means flags, and only flags. This is the ordinary shell
	// bargain and it is what keeps the list readable: `byn audit <TAB>` should
	// answer "tail, view, verify, reseal", not bury those four among thirteen
	// options nobody asked about yet.
	if strings.HasPrefix(cur, "-") {
		return filterPrefix(dedupe(flags), cur)
	}

	// Positional candidates, only in the slot immediately after the command.
	var candidates []string
	if len(prior) == 1 {
		candidates = append(candidates, completionSubcommands[cmd]...)
		switch cmd {
		case "exec":
			candidates = append(candidates, execAliases()...)
		case "help":
			candidates = append(candidates, completionCommands...)
		case "completion":
			candidates = append(candidates, completionShells...)
		}
	}
	// A command with nothing positional to offer falls back to its flags, so
	// `byn doctor <TAB>` still answers something useful rather than nothing.
	if len(candidates) == 0 {
		candidates = flags
	}
	return filterPrefix(dedupe(candidates), cur)
}

// canonicalCommand maps an alias to the command whose help defines its flags,
// so `byn ls --<TAB>` offers what `byn list` documents.
func canonicalCommand(cmd string) string {
	switch cmd {
	case "ls":
		return "list"
	case "rm":
		return "delete"
	case "mv":
		return "rename"
	case "cat":
		return "get"
	case "view":
		return "edit"
	case "ui":
		return "web"
	case "password":
		return "passwd"
	}
	return cmd
}

func filterPrefix(in []string, prefix string) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// runCompleteHidden is the `byn __complete` backend the shell scripts call. It
// prints one candidate per line and always exits 0: a non-zero exit or an error
// on stdout would be rendered by the shell as a completion candidate.
func runCompleteHidden(args []string) int {
	for _, c := range completeWords(args) {
		fmt.Println(c)
	}
	return exitOK
}

// ---- `byn completion <shell>` ------------------------------------------

// completionShells are the shells byn can emit a script for.
var completionShells = []string{"bash", "zsh", "fish"}

//go:embed completions/bash.sh
var completionBash string

//go:embed completions/zsh.sh
var completionZsh string

//go:embed completions/fish.sh
var completionFish string

// runCompletion prints the completion script for a shell.
func runCompletion(args []string, _ cliScope) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: byn completion %s\n", strings.Join(completionShells, "|"))
		return exitErr
	}
	switch args[0] {
	case "bash":
		fmt.Print(completionBash)
	case "zsh":
		fmt.Print(completionZsh)
	case "fish":
		fmt.Print(completionFish)
	case "help", "-h", "--help":
		fmt.Print(helpFor("completion"))
	default:
		fmt.Fprintf(os.Stderr, "byn completion: unknown shell %q (want %s)\n",
			args[0], strings.Join(completionShells, ", "))
		return exitErr
	}
	return exitOK
}
