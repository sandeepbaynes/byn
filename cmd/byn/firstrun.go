package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// isNotInitErr reports whether err is the daemon's "vault does not exist yet"
// reply.
func isNotInitErr(err error) bool {
	var er *ipc.ErrResponse
	return errors.As(err, &er) && er.Code == ipc.CodeNotInit
}

// offerVaultInit creates a vault the user has just tried to use, after asking
// for a password for it.
//
// Storing your first secret should not require knowing that a vault is a thing
// that must exist first. The old flow answered `byn put API_KEY` with "vault
// not initialized — try byn init", which is a step byn can take itself: the
// user has already said what they want, and the only thing byn actually needs
// from them is a password.
//
// Returns true when a vault now exists and the caller should retry. Anything
// non-interactive returns false untouched — creating a vault is not something
// to do silently on behalf of a script that may simply have the wrong name.
func offerVaultInit(c *ipc.Client, vaultName string, jsonMode bool) bool {
	if jsonMode || !stdinIsTTY() {
		return false
	}
	name := vaultName
	if name == "" {
		name = "default"
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", yellow("No vault yet."),
		dim(fmt.Sprintf("Creating %q — choose a master password for it.", name)))
	fmt.Fprintf(os.Stderr, "%s\n",
		dim("It cannot be recovered if you lose it, and byn never sends it anywhere."))

	pwBuf, err := auth.PromptStdinSecure("New master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return false
	}
	defer pwBuf.Wipe()
	if len(pwBuf.Bytes()) < minMasterPasswordLen {
		fmt.Fprintf(os.Stderr, "%s password must be at least %d characters\n",
			boldRed("Error:"), minMasterPasswordLen)
		return false
	}
	confirmBuf, err := auth.PromptStdinSecure("Confirm master password: ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return false
	}
	defer confirmBuf.Wipe()
	if !bytes.Equal(pwBuf.Bytes(), confirmBuf.Bytes()) {
		fmt.Fprintf(os.Stderr, "%s passwords do not match\n", boldRed("Error:"))
		return false
	}

	if cerr := c.Call(ipc.OpVaultInit,
		ipc.VaultInitReq{Name: vaultName, Password: pwBuf.Bytes()}, &ipc.VaultInitResp{}); cerr != nil {
		handleCallError(cerr)
		return false
	}
	// Unlock right away. A vault created seconds ago and immediately locked
	// would make the very next step fail for a second reason, which is exactly
	// the stop-start this is meant to remove.
	var unlockResp ipc.VaultUnlockResp
	if uerr := c.Call(ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: vaultName, Password: pwBuf.Bytes()}, &unlockResp); uerr != nil {
		fmt.Fprintf(os.Stderr, "%s %s\n", yellow("Note:"),
			dim("vault created but not unlocked; run `byn unlock`"))
		return false
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", cyan("Created"), dim("vault "+name+" — carrying on."))
	return true
}

// minMasterPasswordLen mirrors the floor `byn init` enforces.
const minMasterPasswordLen = 8
