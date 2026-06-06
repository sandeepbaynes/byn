// `byn trust` — manage the TOFU trust store for `.byn` files.
//
//	byn trust [PATH]            Trust the .byn at PATH (default: CWD/.byn)
//	byn trust list              List trusted paths
//	byn untrust [PATH]          Revoke trust for PATH (default: CWD/.byn)
//
// Granting trust ALWAYS requires the master password — even when the vault is
// unlocked — because granting is a proof-of-presence action, not an ambient
// one (see docs/security.md, "owned by you, operated by many"). The daemon
// owns the trust store and verifies the password; the CLI never writes it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

func runTrust(args []string, _ cliScope) int {
	if len(args) > 0 {
		switch args[0] {
		case "list", "ls":
			return runTrustList(args[1:])
		case "help", "--help", "-h":
			printTrustUsage(os.Stdout)
			return exitOK
		}
	}
	return runTrustAdd(args)
}

func runTrustAdd(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin instead of prompting")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	path := defaultBynPath(fs)
	body, err := os.ReadFile(path) // #nosec G304 -- user-named
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	vaultName := bynTargetVault(body)

	// Loud warning when this is a RE-approval of a file that changed since it
	// was last trusted — the user is about to trust new content.
	if st, _ := trust.Status(dir, trust.Canonicalize(path), trust.Hash(body)); st == trust.StatusChanged {
		fmt.Fprintln(os.Stderr, boldYellow("Warning:")+" this .byn has CHANGED since you last trusted it.")
		fmt.Fprintln(os.Stderr, dim("  Approving will trust the NEW content. Press Ctrl-C now if that's unexpected."))
	}

	pw, wipe, perr := trustGrantPassword(*pwStdin, vaultName)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
		return exitErr
	}
	defer wipe()

	var resp ipc.TrustGrantResp
	if cerr := newClient(dir).Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: path, Vault: vaultName, Password: pw}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	verb := "Trusted"
	if resp.Changed {
		verb = "Re-trusted (content changed)"
	}
	hintf("%s %s (sha256=%s).", verb, resp.Path, resp.SHA256[:12])
	return exitOK
}

func runUntrust(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("untrust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	path := defaultBynPath(fs)
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	canon := trust.Canonicalize(path)
	var resp ipc.TrustRemoveResp
	if cerr := newClient(dir).Call(ipc.OpTrustRemove, ipc.TrustRemoveReq{Path: canon}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if !resp.Removed {
		fmt.Fprintf(os.Stderr, "(%s was not trusted)\n", canon)
		return exitOK
	}
	hintf("Untrusted %s.", canon)
	return exitOK
}

func runTrustList(args []string) int {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	var resp ipc.TrustListResp
	if cerr := newClient(dir).Call(ipc.OpTrustList, ipc.TrustListReq{}, &resp); cerr != nil {
		return handleCallError(cerr)
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp.Entries, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	if len(resp.Entries) == 0 {
		fmt.Fprintln(os.Stderr, "(no trusted .byn files)")
		return exitOK
	}
	for _, e := range resp.Entries {
		fmt.Printf("%-12s  %s\n", e.SHA256[:12], e.Path)
	}
	return exitOK
}

// bynTargetVault returns the vault named in a .byn's [scope] (empty when
// unspecified or unparseable — the daemon then gates on the default vault).
// The target vault's master password is what authorizes trusting the file.
func bynTargetVault(body []byte) string {
	var parsed dotBynScope
	dec := toml.NewDecoder(strings.NewReader(string(body))).DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return ""
	}
	return parsed.Scope.Vault
}

// trustGrantPassword obtains the master password that authorizes a trust grant.
// It is ALWAYS required (proof-of-presence). The returned wipe func MUST be
// deferred.
func trustGrantPassword(pwStdin bool, vaultName string) (pw []byte, wipe func(), err error) {
	if pwStdin {
		pw, err = readPasswordStdin()
		if err != nil {
			return nil, func() {}, err
		}
		return pw, func() { zero(pw) }, nil
	}
	target := vaultName
	if target == "" {
		target = "default"
	}
	fmt.Fprintln(os.Stderr, yellow("Granting trust requires the master password")+
		dim(" — proof you're present, even if the vault is unlocked."))
	buf, err := auth.PromptStdinSecure(fmt.Sprintf("Master password for vault %q: ", target))
	if err != nil {
		return nil, func() {}, err
	}
	return buf.Bytes(), buf.Wipe, nil
}

func defaultBynPath(fs *flag.FlagSet) string {
	if fs.NArg() >= 1 {
		return fs.Arg(0)
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, ".byn")
}

func printTrustUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, `byn trust — manage TOFU trust for .byn files

Granting trust ALWAYS prompts for the master password (proof of presence),
even when the vault is unlocked. The daemon records the approval; discovery
never auto-trusts a new or changed .byn.

Usage:
  byn trust [PATH]              Trust the .byn at PATH (default: ./.byn)
  byn trust [PATH] --password-stdin
                                Read the master password from stdin (scripts)
  byn trust list [--json]       List currently trusted paths
  byn untrust [PATH]            Revoke trust (default: ./.byn)`)
}
