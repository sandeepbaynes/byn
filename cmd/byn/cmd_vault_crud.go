// Vault management subcommand router and handlers.
//
// `byn vault list` — list all vaults on disk
// `byn vault delete NAME` — remove a vault (refuses default)
// `byn vault init` — alias for `byn init` (delegates)
//
// The lifecycle commands (init/unlock/lock) remain top-level for
// muscle-memory reasons. `byn vault list` is the discovery surface.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runVault(args []string, scope cliScope) int {
	if len(args) == 0 {
		printVaultUsage(os.Stderr)
		return exitErr
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return runVaultList(rest)
	case "delete", "rm":
		return runVaultDelete(rest, scope)
	case "rename", "mv":
		return runVaultRename(rest, scope)
	case "init":
		return runInit(rest, scope)
	case "unlock":
		return runUnlock(rest, scope)
	case "lock":
		return runLock(rest, scope)
	case "passwd", "password":
		return runPasswd(rest, scope)
	case "help", "--help", "-h":
		printVaultUsage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "byn vault: unknown subcommand %q\n", sub)
		printVaultUsage(os.Stderr)
		return exitErr
	}
}

func runVaultList(args []string) int {
	fs := flag.NewFlagSet("vault list", flag.ContinueOnError)
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
	var resp ipc.VaultListResp
	if err := newClient(dir, "").Call(ipc.OpVaultList, ipc.VaultListReq{}, &resp); err != nil {
		return handleCallError(err)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Vaults, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Vaults) == 0 {
		fmt.Fprintln(os.Stderr, "(no vaults initialized — run `byn init` to create one)")
		return exitOK
	}
	for _, v := range resp.Vaults {
		state := "locked"
		if !v.Initialized {
			state = "uninitialized"
		} else if !v.Locked {
			state = "unlocked"
		}
		fmt.Printf("%-20s  %s\n", v.Name, state)
	}
	return exitOK
}

func runVaultDelete(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("vault delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	name := scope.Vault
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn vault delete [NAME]")
		return exitErr
	}
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: vault name required (positional or --vault)")
		return exitErr
	}
	if name == "default" {
		fmt.Fprintln(os.Stderr, "Error: refusing to delete the default vault")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, name).Call(ipc.OpVaultDelete,
			ipc.VaultDeleteReq{Name: name, Password: pw}, &ipc.VaultDeleteResp{})
	})
	if rc == exitOK {
		hintf("Deleted vault %q (all projects, envs, entries gone).", name)
	}
	return rc
}

// runVaultRename renames a vault. Accepts "OLD NEW", or "NEW" with the
// source given via --vault. A locked vault is renamed with the password
// (prompted, or --password-stdin). The vault is left LOCKED afterwards.
func runVaultRename(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("vault rename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	var oldName, newName string
	switch fs.NArg() {
	case 2:
		oldName, newName = fs.Arg(0), fs.Arg(1)
	case 1:
		oldName, newName = scope.Vault, fs.Arg(0)
	default:
		fmt.Fprintln(os.Stderr, "Usage: byn vault rename OLD NEW   (or `byn --vault OLD vault rename NEW`)")
		return exitErr
	}
	if oldName == "" {
		fmt.Fprintln(os.Stderr, "Error: source vault name required (positional or --vault)")
		return exitErr
	}
	if oldName == "default" {
		fmt.Fprintln(os.Stderr, "Error: refusing to rename the default vault")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, oldName).Call(ipc.OpVaultRename,
			ipc.VaultRenameReq{OldName: oldName, NewName: newName, Password: pw},
			&ipc.VaultRenameResp{})
	})
	if rc == exitOK {
		hintf("Renamed vault %q → %q. It is now locked — run `byn --vault %s unlock`.", oldName, newName, newName)
	}
	return rc
}

func printVaultUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn vault — manage vaults

Usage:
  byn vault list [--json]               List vaults on disk
  byn vault delete NAME                 Remove a vault (refuses "default")
  byn vault rename OLD NEW              Rename a vault (refuses "default")
  byn vault passwd                      Change the master password
  byn vault init                        Alias for `+"`byn init`"+`
  byn vault unlock                      Alias for `+"`byn unlock`"+`
  byn vault lock                        Alias for `+"`byn lock`"+``)
}
