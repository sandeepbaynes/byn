// Env management subcommand router and handlers.
//
// `byn env create NAME`            create env in the active project
// `byn env list`                   list envs in the active project
// `byn env delete NAME`            remove a non-default env
// `byn env clear [ENV] --yes`      delete all vars in an env (keep the env)
// `byn env rename OLD NEW`         rename
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runEnv(args []string, scope cliScope) int {
	if len(args) == 0 {
		printEnvUsage(os.Stderr)
		return exitErr
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create", "add":
		return runEnvCreate(rest, scope)
	case "list", "ls":
		return runEnvList(rest, scope)
	case "delete", "rm":
		return runEnvDelete(rest, scope)
	case "clear":
		return runEnvClear(rest, scope)
	case "rename", "mv":
		return runEnvRename(rest, scope)
	case "help", "--help", "-h":
		printEnvUsage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn env: unknown subcommand %q\n", sub)
		printEnvUsage(os.Stderr)
		return exitErr
	}
}

func projectOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func vaultOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func runEnvCreate(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("env create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	name := scope.Env
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn env create NAME")
		return exitErr
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: env name required (positional or --env)")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if err := newClient(dir, scope.Vault).Call(ipc.OpEnvCreate,
		ipc.EnvCreateReq{Vault: scope.Vault, Project: projectOrDefault(scope.Project), Name: name},
		&ipc.EnvCreateResp{}); err != nil {
		return handleCallError(err)
	}
	hintf("Created env %q in %s/%s.", name, vaultOrDefault(scope.Vault), projectOrDefault(scope.Project))
	return exitOK
}

func runEnvList(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("env list", flag.ContinueOnError)
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
	var resp ipc.EnvListResp
	if err := newClient(dir, scope.Vault).Call(ipc.OpEnvList,
		ipc.EnvListReq{Vault: scope.Vault, Project: projectOrDefault(scope.Project)},
		&resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Envs, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Envs) == 0 {
		fmt.Fprintln(os.Stderr, "(no envs)")
		return exitOK
	}
	for _, e := range resp.Envs {
		marker := ""
		if e.IsDefault {
			marker = " (default)"
		}
		fmt.Printf("%s%s\n", e.Name, marker)
	}
	return exitOK
}

func runEnvDelete(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("env delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	name := scope.Env
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn env delete NAME")
		return exitErr
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: env name required (positional or --env)")
		return exitErr
	}
	if name == "default" {
		fmt.Fprintln(os.Stderr, "Error: refusing to delete the default env")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpEnvDelete,
			ipc.EnvDeleteReq{Vault: scope.Vault, Project: projectOrDefault(scope.Project), Name: name, Password: pw},
			&ipc.EnvDeleteResp{})
	})
	if rc == exitOK {
		hintf("Deleted env %q from %s/%s.", name, vaultOrDefault(scope.Vault), projectOrDefault(scope.Project))
	}
	return rc
}

// runEnvClear deletes ALL env-vars in an env (the env itself is kept).
// Destructive, so it requires --yes; without it, prints a preview and exits.
func runEnvClear(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("env clear", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	yes := fs.Bool("yes", false, "confirm the deletion (without it, prints a preview and exits non-zero)")
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	target := scope.Env
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn env clear [ENV] --yes")
		return exitErr
	}
	if target == "" {
		target = "default"
	}
	vlt, prj := vaultOrDefault(scope.Vault), projectOrDefault(scope.Project)
	if !*yes {
		fmt.Fprintf(os.Stderr, "%s deletes ALL env-vars in env %q of %s/%s (inherited values are kept).\n",
			boldYellow("env clear"), target, vlt, prj)
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Confirm with"), cyan("byn env clear "+target+" --yes"))
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	clearScope := scope
	clearScope.Env = target
	var resp ipc.EnvClearResp
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpEnvClear,
			ipc.EnvClearReq{Scope: clearScope.ToIPC(), Password: pw}, &resp)
	})
	if rc == exitOK {
		hintf("Cleared %d env-var(s) from %s/%s/%s.", resp.Deleted, vlt, prj, target)
	}
	return rc
}

func runEnvRename(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("env rename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn env rename OLD NEW")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	old, neu := fs.Arg(0), fs.Arg(1)
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpEnvRename,
			ipc.EnvRenameReq{Vault: scope.Vault, Project: projectOrDefault(scope.Project), OldName: old, NewName: neu, Password: pw},
			&ipc.EnvRenameResp{})
	})
	if rc == exitOK {
		hintf("Renamed env %q → %q in %s/%s.", old, neu, vaultOrDefault(scope.Vault), projectOrDefault(scope.Project))
	}
	return rc
}

func printEnvUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn env — manage envs within a project

Usage:
  byn env list [--json]                 List envs
  byn env create NAME                   Create a non-default env
  byn env delete NAME                   Remove a non-default env
  byn env clear [ENV] --yes             Delete all vars in an env (keeps the env)
  byn env rename OLD NEW                Rename`)
}
