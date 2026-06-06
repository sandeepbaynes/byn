// `byn` (no args) and `byn edit` / `byn view` open the
// modal TUI from the internal/tui package.
//
// This file is a thin entrypoint: it bootstraps daemon connectivity,
// unlocks the active vault on demand, then hands off to the
// bubbletea Program. All TUI logic lives under internal/tui/.
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/tui"
)

func runTUI(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("byn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "Error: byn TUI requires a terminal (stdout/stdin is piped or redirected)")
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	client := newClient(dir)

	// Status check + unlock prompt loop for the *targeted* vault
	// (defaults to "default" if --vault wasn't passed). This is what
	// the user expects: `byn --vault work edit` should boot into
	// the work vault, not silently fall back to default.
	targetVault := scope.Vault
	if targetVault == "" {
		targetVault = "default"
	}
	var status ipc.StatusResp
	if err := client.Call(ipc.OpStatus, ipc.StatusReq{}, &status); err != nil {
		return handleCallError(err)
	}
	locked, exists := vaultStateByName(status, targetVault)
	if !exists {
		fmt.Fprintf(os.Stderr, "%s %s\n",
			boldRed("Error:"),
			red(fmt.Sprintf("Vault %q is not initialized.", targetVault)))
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Run:"), cyan("byn --vault "+targetVault+" init"))
		fmt.Fprintf(os.Stderr, "\n%s\n", dim(fmt.Sprintf("(Vault dir: %s — override with BYN_DIR)", dir)))
		return exitErr
	}
	if locked {
		pwBuf, err := auth.PromptStdinSecure(fmt.Sprintf("Master password for %q: ", targetVault))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
			return exitErr
		}
		defer pwBuf.Wipe()
		if err := client.Call(ipc.OpVaultUnlock,
			ipc.VaultUnlockReq{Name: targetVault, Password: pwBuf.Bytes()},
			&ipc.VaultUnlockResp{}); err != nil {
			return handleCallError(err)
		}
	}

	if err := tui.Run(client, scope.ToIPC(), version); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	return exitOK
}

// defaultVaultState scans a StatusResp for the "default" vault entry
// and reports whether it exists and whether it's locked.
func defaultVaultState(status ipc.StatusResp) (locked, exists bool) {
	return vaultStateByName(status, "default")
}

// vaultStateByName looks up a named vault in the status snapshot.
func vaultStateByName(status ipc.StatusResp, name string) (locked, exists bool) {
	for _, v := range status.Vaults {
		if v.Name == name {
			return v.Locked, true
		}
	}
	return false, false
}
