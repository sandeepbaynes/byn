package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runPasswd changes a vault's master password. Only the wrapping key
// changes; the vault's data and lock state are untouched. The current
// password is required (a forgotten password is unrecoverable by design).
//
//	byn passwd                    # interactive: current, new, confirm
//	byn passwd --vault work       # target a non-default vault
//	byn passwd --password-stdin   # read current then new from stdin (2 lines)
func runPasswd(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read current then new password from stdin (two lines)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	var oldPw, newPw []byte
	if *pwStdin {
		oldPw, newPw, err = readTwoPasswordsStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer zero(oldPw)
		defer zero(newPw)
	} else {
		curBuf, perr := auth.PromptStdinSecure("Current master password: ")
		if perr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", perr)
			return exitErr
		}
		defer curBuf.Wipe()
		newBuf, perr := auth.PromptStdinSecure("New master password: ")
		if perr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", perr)
			return exitErr
		}
		defer newBuf.Wipe()
		confBuf, perr := auth.PromptStdinSecure("Confirm new master password: ")
		if perr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", perr)
			return exitErr
		}
		defer confBuf.Wipe()
		if !bytes.Equal(newBuf.Bytes(), confBuf.Bytes()) {
			fmt.Fprintln(os.Stderr, "Error: new passwords do not match")
			return exitErr
		}
		oldPw = curBuf.Bytes()
		newPw = newBuf.Bytes()
	}
	if len(newPw) < 8 {
		fmt.Fprintln(os.Stderr, "Error: new password must be at least 8 characters")
		return exitErr
	}

	err = newClient(dir, scope.Vault).Call(ipc.OpVaultPasswd,
		ipc.VaultPasswdReq{Name: scope.Vault, OldPassword: oldPw, NewPassword: newPw},
		&ipc.VaultPasswdResp{})
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	hintf("Changed master password for vault %q.", vaultOrDefault(scope.Vault))
	return exitOK
}

// readTwoPasswordsStdin reads two newline-separated lines from stdin — the
// current password then the new one — for scripted `passwd --password-stdin`.
func readTwoPasswordsStdin() (oldPw, newPw []byte, err error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, nil, fmt.Errorf("read stdin: %w", err)
	}
	lines := bytes.SplitN(data, []byte("\n"), 3)
	if len(lines) < 2 {
		return nil, nil, errors.New("expected two lines on stdin: current password, then new password")
	}
	oldPw = bytes.TrimRight(lines[0], "\r")
	newPw = bytes.TrimRight(lines[1], "\r")
	return oldPw, newPw, nil
}
