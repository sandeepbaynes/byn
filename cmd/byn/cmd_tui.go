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
	client := newClient(dir, scope.Vault)

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
		fmt.Fprintf(os.Stderr, "\n%s\n", dim(fmt.Sprintf("(Vault dir: %s)", dir)))
		return exitErr
	}
	if locked {
		pwBuf, err := auth.PromptStdinSecure(fmt.Sprintf("Master password for %q: ", targetVault))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
			return exitErr
		}
		defer pwBuf.Wipe()
		// Use CallAndCaptureSession so the minted session token is stored on
		// the client and threaded into every subsequent TUI op.  This gives
		// the TUI the same "unlock once per terminal" experience as the CLI:
		// value reads inside the TUI don't re-prompt for a password.
		//
		// Because the TUI's ipc.Client is the same object passed to tui.Run,
		// setting client.Session here propagates to all future data.go commands.
		// The token is also written to the per-TTY session file so that CLI
		// commands run in the same terminal after the TUI exits also benefit
		// (consistent with `byn unlock` saving to the per-TTY file).
		var unlockResp ipc.VaultUnlockResp
		tok, cerr := client.CallAndCaptureSession(ipc.OpVaultUnlock,
			ipc.VaultUnlockReq{Name: targetVault, Password: pwBuf.Bytes()},
			&unlockResp, client.Session)
		if cerr != nil {
			return handleCallError(cerr)
		}
		// Prefer the session token from the envelope header (tok); fall back to
		// the response body field for daemons that only set one of them.
		if len(tok) == 0 {
			tok = unlockResp.SessionToken
		}
		if len(tok) > 0 {
			client.Session = tok
			vaultKey := vaultSessionKey(targetVault)
			if serr := saveSessionToken(sessionStoreDir(dir), vaultKey, tok); serr != nil {
				// Non-fatal: TUI already has the session; file is convenience.
				fmt.Fprintf(os.Stderr, "warning: could not save session token: %v\n", serr)
			}
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
