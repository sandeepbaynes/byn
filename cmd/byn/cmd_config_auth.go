package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runConfigAuth proves the operator has sudo (via `sudo -v` → PAM) and, on
// success, mints a SINGLE-USE config-WRITE token over the UID-gated daemon socket
// and prints it. The operator pastes the code into the portal Settings panel to
// authorize exactly ONE config write (e.g. enabling [security] privsep).
//
// Why this exists: under privsep the config file is _byn-owned, so the portal
// (running as _byn) is the only thing that can rewrite it — but a plain portal
// session (reachable by any same-UID process) must NOT be able to weaken security
// settings. Gating config WRITES behind a fresh sudo-verified, single-use token
// makes "change byn's security posture" require the OS sudo password every time.
// byn never sees that password — `sudo -v` hands it to PAM.
func runConfigAuth(args []string) int {
	_ = args
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	// Prove sudo via PAM. `sudo -v` prompts for the OS password (or refreshes a
	// valid sudo timestamp) and exits 0 only if the user is a sudoer who
	// authenticated. Stdio is inherited so the prompt reaches the terminal.
	scmd := exec.Command("sudo", "-v")
	scmd.Stdin, scmd.Stdout, scmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if rerr := scmd.Run(); rerr != nil {
		fmt.Fprintln(os.Stderr, boldRed("Error:")+" sudo verification failed — config changes require sudo.")
		return exitErr
	}

	var resp ipc.ConfigAuthResp
	if cerr := newClient(dir, "").Call(ipc.OpConfigAuth, ipc.ConfigAuthReq{}, &resp); cerr != nil {
		fmt.Fprintln(os.Stderr, boldRed("Error:")+" byn daemon is not running.")
		fmt.Fprintln(os.Stderr, yellow("Run:")+"   "+cyan("byn start"))
		return exitDaemonDown
	}

	fmt.Println("Config write authorized. Paste this one-time code into the portal Settings panel:")
	fmt.Println()
	fmt.Println("  " + resp.Token)
	fmt.Println()
	fmt.Println("It is single-use and expires in 60 seconds. Run byn config-auth again for the next change.")
	return exitOK
}
