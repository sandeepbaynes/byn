package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// `byn describe` and `byn note` — the two halves of commentary, kept as two
// commands because they are for two different readers.
//
// describe writes the plaintext line a tool reads to learn what a variable is
// for. note writes the owner's private text, encrypted like a value. Putting
// them behind one command with a flag would make it easy to type the wrong one,
// and the cost of that mistake is a private thought published to every process
// that can reach the socket.

// parseTarget turns a command-line target into the wire form.
//
// A bare NAME is a variable in the current scope — the overwhelmingly common
// case, and the one worth spending the short spelling on. Anything else is
// TYPE:REF: "project:web", "vault:", "run:42".
func parseTarget(s string) (ipc.AnnotationTarget, error) {
	typ, ref, found := strings.Cut(s, ":")
	if !found {
		return ipc.AnnotationTarget{Type: string(vault.ObjectEntry), Name: s}, nil
	}
	switch vault.ObjectType(typ) {
	case vault.ObjectEntry, vault.ObjectProject, vault.ObjectEnv:
		if ref == "" {
			// "project:" means the scope's own project.
			return ipc.AnnotationTarget{Type: typ}, nil
		}
		return ipc.AnnotationTarget{Type: typ, Name: ref}, nil
	case vault.ObjectVault:
		return ipc.AnnotationTarget{Type: typ}, nil
	case vault.ObjectTrust, vault.ObjectRun, vault.ObjectPasskey:
		id, err := strconv.ParseInt(ref, 10, 64)
		if err != nil || id <= 0 {
			return ipc.AnnotationTarget{}, fmt.Errorf("%s needs a numeric id, as in %s:42", typ, typ)
		}
		return ipc.AnnotationTarget{Type: typ, ID: id}, nil
	default:
		return ipc.AnnotationTarget{}, fmt.Errorf(
			"unknown target %q: use a variable name, or one of vault:, project:NAME, env:NAME, entry:NAME, trust:ID, run:ID, passkey:ID", typ)
	}
}

func targetLabel(t ipc.AnnotationTarget) string {
	switch {
	case t.Name != "":
		return t.Type + " " + t.Name
	case t.ID > 0:
		return t.Type + " " + strconv.FormatInt(t.ID, 10)
	default:
		return "the " + t.Type
	}
}

// runDescribe implements `byn describe`.
func runDescribe(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("describe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	clear := fs.Bool("clear", false, "remove the description (its text stays in history)")
	history := fs.Bool("history", false, "show every version of the description, oldest first")
	jsonOut := fs.Bool("json", false, "emit JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: byn describe <target> [text] | --clear | --history")
		return exitErr
	}
	target, err := parseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	switch {
	case *history:
		return showDescriptionHistory(dir, scope, target, *jsonOut, *pwStdin)
	case *clear:
		rc := mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, func(pw []byte) error {
			return newClient(dir, scope.Vault).Call(ipc.OpAnnotationSet, ipc.AnnotationSetReq{
				Scope: scope.ToIPC(), Target: target, Clear: true, Password: pw,
			}, &ipc.AnnotationSetResp{})
		})
		if rc == exitOK && !*jsonOut {
			hintf("Cleared the description on %s. Its text is still in `byn describe %s --history`.",
				targetLabel(target), fs.Arg(0))
		}
		return rc
	case fs.NArg() == 1:
		return showDescription(dir, scope, target, *jsonOut)
	}

	text := strings.Join(fs.Args()[1:], " ")
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationSet, ipc.AnnotationSetReq{
			Scope: scope.ToIPC(), Target: target, Text: text, Password: pw,
		}, &ipc.AnnotationSetResp{})
	})
	if rc == exitOK && !*jsonOut {
		hintf("Described %s. This is readable by anything that can reach byn, including agents.",
			targetLabel(target))
	}
	return rc
}

func showDescription(dir string, scope cliScope, target ipc.AnnotationTarget, jsonOut bool) int {
	var resp ipc.AnnotationListResp
	err := newClient(dir, scope.Vault).Call(ipc.OpAnnotationList, ipc.AnnotationListReq{
		Scope: scope.ToIPC(), Target: target, Kind: vault.KindDescription,
	}, &resp)
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	if jsonOut {
		out, _ := json.MarshalIndent(resp.Descriptions, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Descriptions) == 0 {
		fmt.Fprintf(os.Stderr, "(no description on %s)\n", targetLabel(target))
		return exitOK
	}
	for _, d := range resp.Descriptions {
		fmt.Println(d.Body)
		if d.Author == vault.AuthorAgent {
			fmt.Fprintf(os.Stderr, "%s written by %s, not by you\n", yellow("note:"), agentLabel(d.AuthorComm))
		}
	}
	return exitOK
}

func showDescriptionHistory(dir string, scope cliScope, target ipc.AnnotationTarget, jsonOut, pwStdin bool) int {
	var cur ipc.AnnotationListResp
	err := newClient(dir, scope.Vault).Call(ipc.OpAnnotationList, ipc.AnnotationListReq{
		Scope: scope.ToIPC(), Target: target, Kind: vault.KindDescription,
	}, &cur)
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	if len(cur.Descriptions) == 0 {
		fmt.Fprintf(os.Stderr, "(no description on %s)\n", targetLabel(target))
		return exitOK
	}
	return showHistory(dir, scope, target, cur.Descriptions[0].ID, jsonOut, pwStdin)
}

// runNote implements `byn note`.
func runNote(args []string, scope cliScope) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: byn note <add|ls|edit|rm|history> <target> [...]")
		return exitErr
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return runNoteAdd(rest, scope)
	case "ls", "list":
		return runNoteList(rest, scope)
	case "edit":
		return runNoteEdit(rest, scope)
	case "rm", "remove":
		return runNoteRemove(rest, scope)
	case "history":
		return runNoteHistory(rest, scope)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand %q\n", sub)
		fmt.Fprintln(os.Stderr, "Usage: byn note <add|ls|edit|rm|history> <target> [...]")
		return exitErr
	}
}

func runNoteAdd(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("note add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn note add <target> <text>")
		return exitErr
	}
	target, err := parseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	text := strings.Join(fs.Args()[1:], " ")
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationAdd, ipc.AnnotationAddReq{
			Scope: scope.ToIPC(), Target: target, Text: text, Password: pw,
		}, &ipc.AnnotationAddResp{})
	})
	if rc == exitOK && !*jsonOut {
		hintf("Noted on %s. Encrypted — only you can read it.", targetLabel(target))
	}
	return rc
}

func runNoteList(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("note ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn note ls <target>")
		return exitErr
	}
	target, err := parseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.AnnotationListResp
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, func(pw []byte) error {
		resp = ipc.AnnotationListResp{}
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationList, ipc.AnnotationListReq{
			Scope: scope.ToIPC(), Target: target, Kind: vault.KindNote, Password: pw,
		}, &resp)
	})
	if rc != exitOK {
		return rc
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Notes, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if resp.NotesWithheld {
		fmt.Fprintf(os.Stderr, "%s %s has %d note(s), and reading them needs the vault open.\n",
			yellow("note:"), targetLabel(target), resp.NoteCount)
		fmt.Fprintln(os.Stderr, "      byn unlock, or pass --password-stdin")
		return exitErr
	}
	if len(resp.Notes) == 0 {
		fmt.Fprintf(os.Stderr, "(no notes on %s)\n", targetLabel(target))
		return exitOK
	}
	for _, n := range resp.Notes {
		who := n.Author
		if n.Author == vault.AuthorAgent {
			who = agentLabel(n.AuthorComm)
		}
		fmt.Printf("%-4d %s  %s\n", n.ID, n.CreatedAt.Format("2006-01-02 15:04"), who)
		for _, line := range strings.Split(n.Body, "\n") {
			fmt.Println("     " + line)
		}
	}
	return exitOK
}

func runNoteEdit(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("note edit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() < 3 {
		fmt.Fprintln(os.Stderr, "Usage: byn note edit <target> <id> <text>")
		return exitErr
	}
	target, id, rc := targetAndID(fs.Arg(0), fs.Arg(1))
	if rc != exitOK {
		return rc
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	text := strings.Join(fs.Args()[2:], " ")
	rc = mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationEdit, ipc.AnnotationEditReq{
			Scope: scope.ToIPC(), Target: target, ID: id, Text: text, Password: pw,
		}, &ipc.AnnotationEditResp{})
	})
	if rc == exitOK {
		hintf("Reworded note %d. The previous text is in `byn note history %s %d`.", id, fs.Arg(0), id)
	}
	return rc
}

func runNoteRemove(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("note rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn note rm <target> <id>")
		return exitErr
	}
	target, id, rc := targetAndID(fs.Arg(0), fs.Arg(1))
	if rc != exitOK {
		return rc
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	rc = mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationRemove, ipc.AnnotationRemoveReq{
			Scope: scope.ToIPC(), Target: target, ID: id, Password: pw,
		}, &ipc.AnnotationRemoveResp{})
	})
	if rc == exitOK {
		// Not a hint. Hints are suppressed when nothing is watching, and this
		// is exactly the case that must not be silent: a person deleting a
		// private note reasonably expects it gone, and it is not.
		fmt.Fprintf(os.Stderr, "%s note %d is out of the listing; its text stays in `byn note history %s %d`.\n",
			yellow("note:"), id, fs.Arg(0), id)
		fmt.Fprintln(os.Stderr, "      A note or description changed to mislead a later reader has to stay traceable.")
	}
	return rc
}

func runNoteHistory(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("note history", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn note history <target> <id>")
		return exitErr
	}
	target, id, rc := targetAndID(fs.Arg(0), fs.Arg(1))
	if rc != exitOK {
		return rc
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	return showHistory(dir, scope, target, id, *jsonOut, *pwStdin)
}

func targetAndID(targetArg, idArg string) (ipc.AnnotationTarget, int64, int) {
	target, err := parseTarget(targetArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ipc.AnnotationTarget{}, 0, exitErr
	}
	id, err := strconv.ParseInt(idArg, 10, 64)
	if err != nil || id <= 0 {
		fmt.Fprintf(os.Stderr, "Error: %q is not an annotation id\n", idArg)
		return ipc.AnnotationTarget{}, 0, exitErr
	}
	return target, id, exitOK
}

func showHistory(dir string, scope cliScope, target ipc.AnnotationTarget, id int64, jsonOut, pwStdin bool) int {
	var resp ipc.AnnotationHistoryResp
	rc := mutateWithAuthRetry(pwStdin, jsonOut, true, nil, func(pw []byte) error {
		resp = ipc.AnnotationHistoryResp{}
		return newClient(dir, scope.Vault).Call(ipc.OpAnnotationHistory, ipc.AnnotationHistoryReq{
			Scope: scope.ToIPC(), Target: target, ID: id, Password: pw,
		}, &resp)
	})
	if rc != exitOK {
		return rc
	}
	if jsonOut {
		out, _ := json.MarshalIndent(resp.Versions, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	for _, v := range resp.Versions {
		who := v.Author
		if v.Author == vault.AuthorAgent {
			who = agentLabel(v.AuthorComm)
		}
		fmt.Printf("v%-3d %s  %-7s %s\n", v.VersionNo, v.CreatedAt.Format("2006-01-02 15:04"), v.Op, who)
		if v.Body != "" {
			for _, line := range strings.Split(v.Body, "\n") {
				fmt.Println("     " + line)
			}
		}
	}
	return exitOK
}

// agentLabel names an unattended author for a person reading a listing. The
// process name is included because "an agent" and "the thing called node" are
// different amounts of information, and the second is the useful one.
func agentLabel(comm string) string {
	if comm == "" {
		return "an agent"
	}
	return "agent (" + comm + ")"
}

// printGetDescriptions writes the context lines that accompany a value shown to
// a person. Every layer is labelled by where it came from, because a .byn's
// description was approved at trust time and one stored in the vault may have
// been written by whatever created the value.
func printGetDescriptions(ds []ipc.DescriptionView) {
	for _, d := range ds {
		who := ""
		switch {
		case d.Source == ".byn":
			who = " [.byn]"
		case d.Author == vault.AuthorAgent:
			who = " [" + agentLabel(d.AuthorComm) + "]"
		}
		fmt.Fprintf(os.Stderr, "%s %s%s\n", dim("#"), d.Text, who)
	}
}

// describedBy prefixes a listed description with where it came from, when that
// is something the reader should weigh. The owner's own words in the vault get
// no prefix — that is the unremarkable case.
func describedBy(s ipc.SecretMeta) string {
	switch {
	case s.DescriptionSource == ".byn":
		return dim("[.byn] ")
	case s.DescriptionAuthor == vault.AuthorAgent:
		return yellow("[" + agentLabel(s.DescriptionComm) + "] ")
	default:
		return ""
	}
}
