// Project management subcommand router and handlers.
//
// `byn project create NAME`            create project in the active vault
// `byn project list`                   list projects in the active vault
// `byn project delete NAME`            cascade-delete project + envs + entries
// `byn project rename OLD NEW`         rename
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runProject(args []string, scope cliScope) int {
	if len(args) == 0 {
		printProjectUsage(os.Stderr)
		return exitErr
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create", "add":
		return runProjectCreate(rest, scope)
	case "list", "ls":
		return runProjectList(rest, scope)
	case "delete", "rm":
		return runProjectDelete(rest, scope)
	case "rename", "mv":
		return runProjectRename(rest, scope)
	case "help", "--help", "-h":
		printProjectUsage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn project: unknown subcommand %q\n", sub)
		printProjectUsage(os.Stderr)
		return exitErr
	}
}

func runProjectCreate(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("project create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	name := scope.Project
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn project create NAME")
		return exitErr
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: project name required (positional or --project)")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if err := newClient(dir).Call(ipc.OpProjectCreate,
		ipc.ProjectCreateReq{Vault: scope.Vault, Name: name},
		&ipc.ProjectCreateResp{}); err != nil {
		return handleCallError(err)
	}
	hintf("Created project %q in vault %q.", name, vaultOrDefault(scope.Vault))
	return exitOK
}

func runProjectList(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("project list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.ProjectListResp
	if err := newClient(dir).Call(ipc.OpProjectList,
		ipc.ProjectListReq{Vault: scope.Vault}, &resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Projects, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Projects) == 0 {
		fmt.Fprintln(os.Stderr, "(no projects — `byn project create NAME` to add one)")
		return exitOK
	}
	for _, p := range resp.Projects {
		fmt.Println(p.Name)
	}
	return exitOK
}

func runProjectDelete(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("project delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	name := scope.Project
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn project delete NAME")
		return exitErr
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: project name required (positional or --project)")
		return exitErr
	}
	if name == "default" {
		fmt.Fprintln(os.Stderr, "Error: refusing to delete the default project")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	rc := mutateWithLockRetry(*pwStdin, func(pw []byte) error {
		return newClient(dir).Call(ipc.OpProjectDelete,
			ipc.ProjectDeleteReq{Vault: scope.Vault, Name: name, Password: pw},
			&ipc.ProjectDeleteResp{})
	})
	if rc == exitOK {
		hintf("Deleted project %q (and its envs + entries) from vault %q.", name, vaultOrDefault(scope.Vault))
	}
	return rc
}

func runProjectRename(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("project rename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn project rename OLD NEW")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	old, neu := fs.Arg(0), fs.Arg(1)
	rc := mutateWithLockRetry(*pwStdin, func(pw []byte) error {
		return newClient(dir).Call(ipc.OpProjectRename,
			ipc.ProjectRenameReq{Vault: scope.Vault, OldName: old, NewName: neu, Password: pw},
			&ipc.ProjectRenameResp{})
	})
	if rc == exitOK {
		hintf("Renamed project %q → %q in vault %q.", old, neu, vaultOrDefault(scope.Vault))
	}
	return rc
}

func printProjectUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn project — manage projects within a vault

Usage:
  byn project list [--json]             List projects
  byn project create NAME               Create a project (and its default env)
  byn project delete NAME               Cascade-delete (envs + entries gone too)
  byn project rename OLD NEW            Rename`)
}
