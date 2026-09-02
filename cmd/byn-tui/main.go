// byn-tui is the modal editor, shipped as its own binary.
//
// It exists as a separate program for one reason: bubbletea's package init calls
// lipgloss.HasDarkBackground(), which asks the terminal for its background
// colour and waits up to five seconds for an answer. That is unconditional in
// bubbletea v1 — the library documents it as a workaround to be removed in v2,
// and there is no v2 — so every command in a binary that merely LINKS bubbletea
// pays it. On a terminal that answers, the cost is invisible. On a controlling
// terminal that does not — a pty with no emulator behind it, which is what
// `script`, serial consoles, CI runners that allocate a tty and some agent
// harnesses give you — `byn version` took 5.1 seconds, and so did every other
// command.
//
// Go initialises imported packages before the importing package, so byn cannot
// pre-empt a dependency's init from its own code. The only way not to run it is
// not to link it. Hence this binary: `byn` no longer imports the TUI, and pays
// nothing.
//
// The alternative was a replace directive onto a patched bubbletea — one line
// removed, no packaging change. It was rejected because a secrets manager should
// not carry a forked dependency to save packaging work.
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/paths"
	"github.com/sandeepbaynes/byn/internal/session"
	"github.com/sandeepbaynes/byn/internal/tui"
)

// version is stamped by the build, matching the byn binary that launched us.
var version = "dev"

const (
	exitOK  = 0
	exitErr = 1
	// exitDaemonErr matches byn's own code for a daemon refusal, so a script
	// driving either binary reads one set of codes.
	exitDaemonErr = 3
	exitUnreach   = 2
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("byn-tui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	vault := fs.String("vault", "", "vault to open")
	project := fs.String("project", "", "project scope")
	env := fs.String("env", "", "env scope")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	// Refused rather than attempted. bubbletea takes over the terminal; without
	// one there is nothing to take over, and the failure it produces otherwise
	// is unreadable.
	if !term.IsTerminal(int(os.Stdout.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "Error: byn TUI requires a terminal (stdout/stdin is piped or redirected)")
		return exitErr
	}

	dir, err := paths.DataDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	scope := ipc.Scope{Vault: *vault, Project: *project, Env: *env}
	client := newClient(dir, *vault)

	target := *vault
	if target == "" {
		target = "default"
	}
	var status ipc.StatusResp
	if cerr := client.Call(ipc.OpStatus, ipc.StatusReq{}, &status); cerr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", cerr)
		return exitUnreach
	}
	locked, exists := vaultStateByName(status, target)
	if !exists {
		fmt.Fprintf(os.Stderr, "Error: vault %q is not initialized.\n", target)
		fmt.Fprintf(os.Stderr, "Run: byn --vault %s init\n", target)
		return exitErr
	}
	if locked {
		if rc := unlock(client, dir, target); rc != exitOK {
			return rc
		}
	}
	if rerr := tui.Run(client, scope, version); rerr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", rerr)
		return exitErr
	}
	return exitOK
}

// unlock prompts for the master password and keeps the session, so reads inside
// the TUI do not ask again — and so a CLI command run in the same terminal
// afterwards inherits it, which is the behaviour `byn unlock` gives.
func unlock(client *ipc.Client, dir, vaultName string) int {
	pwBuf, err := auth.PromptStdinSecure(fmt.Sprintf("Master password for %q: ", vaultName))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	defer pwBuf.Wipe()

	var resp ipc.VaultUnlockResp
	tok, cerr := client.CallAndCaptureSession(ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: vaultName, Password: pwBuf.Bytes()}, &resp, client.Session)
	if cerr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", cerr)
		return exitDaemonErr
	}
	// Prefer the envelope header; fall back to the body for daemons that set
	// only one of them.
	if len(tok) == 0 {
		tok = resp.SessionToken
	}
	if len(tok) == 0 {
		return exitOK
	}
	client.Session = tok
	key := session.VaultKey(vaultName)
	if _, serr := session.SaveTokenForThisTTY(session.StoreDir(dir), key, tok); serr != nil {
		// Non-fatal: the TUI already holds the session; the file is a
		// convenience for commands run afterwards in the same terminal.
		fmt.Fprintf(os.Stderr, "warning: could not save session token: %v\n", serr)
	}
	return exitOK
}

// newClient dials the daemon and picks up any session already established in
// this terminal, so launching the TUI after `byn unlock` does not ask again.
func newClient(dir, vault string) *ipc.Client {
	sock, err := paths.ActiveSocketPath(dir)
	if err != nil {
		sock = dir + "/" + daemon.SocketFilename
	}
	c := ipc.NewClient(sock)
	if tok := session.LoadToken(session.StoreDir(dir), session.VaultKey(vault)); len(tok) > 0 {
		c.Session = tok
	}
	return c
}

// vaultStateByName looks up a named vault in a status snapshot.
func vaultStateByName(status ipc.StatusResp, name string) (locked, exists bool) {
	for _, v := range status.Vaults {
		if v.Name == name {
			return v.Locked, true
		}
	}
	return false, false
}
