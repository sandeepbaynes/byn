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
	"io/fs"
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

// runTrustAdd trusts one or many .byn files. Paths come from positional args
// and/or --paths (comma-separated); a directory resolves to <dir>/.byn, and
// --recursive walks directories for every .byn. Files are grouped by their
// target vault so each vault's password is prompted exactly once, and the bulk
// daemon op verifies that password a single time for the whole group.
func runTrustAdd(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin instead of prompting")
	pathsCSV := fs.String("paths", "", "comma-separated .byn files or directories to trust")
	recursive := fs.Bool("recursive", false, "walk each given directory for every .byn under it")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	inputs := append([]string{}, fs.Args()...)
	for _, p := range strings.Split(*pathsCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			inputs = append(inputs, p)
		}
	}
	paths := resolveBynPaths(inputs, *recursive)
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "%s no .byn files found to trust\n", boldRed("Error:"))
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	// Group paths by each file's target vault; count changed files for one warning.
	byVault := map[string][]string{}
	var vaultOrder []string
	changed := 0
	for _, p := range paths {
		body, rerr := os.ReadFile(p) // #nosec G304 -- user-named
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "  %s %s: %v\n", red("skip"), p, rerr)
			continue
		}
		if st, _ := trust.Status(dir, trust.Canonicalize(p), trust.Hash(body)); st == trust.StatusChanged {
			changed++
		}
		v := bynTargetVault(body)
		if v == "" {
			v = "default"
		}
		if _, ok := byVault[v]; !ok {
			vaultOrder = append(vaultOrder, v)
		}
		byVault[v] = append(byVault[v], p)
	}
	if len(vaultOrder) == 0 {
		return exitErr
	}
	if *pwStdin && len(vaultOrder) > 1 {
		fmt.Fprintf(os.Stderr, "%s these .byn files span %d vaults; --password-stdin can't supply multiple passwords.\n",
			boldRed("Error:"), len(vaultOrder))
		fmt.Fprintf(os.Stderr, "%s run interactively, or trust one vault's files at a time.\n", yellow("Hint:"))
		return exitErr
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "%s %d of these .byn file(s) CHANGED since last trusted — approving trusts the NEW content.\n",
			boldYellow("Warning:"), changed)
	}

	multi := len(paths) > 1 || len(vaultOrder) > 1
	trusted, failed := 0, 0
	for _, v := range vaultOrder {
		pw, wipe, perr := trustGrantPassword(*pwStdin, v)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
			return exitErr
		}
		var resp ipc.TrustGrantBulkResp
		cerr := newClient(dir).Call(ipc.OpTrustGrantBulk,
			ipc.TrustGrantBulkReq{Paths: byVault[v], Vault: v, Password: pw}, &resp)
		wipe()
		if cerr != nil {
			return handleCallError(cerr)
		}
		for _, r := range resp.Results {
			if r.Error != "" {
				fmt.Fprintf(os.Stderr, "  %s %s: %s\n", red("x"), r.Path, r.Error)
				failed++
				continue
			}
			trusted++
			if !multi {
				verb := "Trusted"
				if r.Changed {
					verb = "Re-trusted (content changed)"
				}
				hintf("%s %s (sha256=%s).", verb, r.Path, r.SHA256[:12])
				continue
			}
			tag := "trusted"
			if r.Changed {
				tag = "re-trusted (changed)"
			}
			fmt.Fprintf(os.Stderr, "  %s %s [%s] %s\n", cyan("+"), r.Path, v, tag)
		}
	}
	if multi {
		extra := ""
		if failed > 0 {
			extra = fmt.Sprintf(" (%d failed)", failed)
		}
		hintf("Trusted %d .byn file(s) across %d vault(s)%s.", trusted, len(vaultOrder), extra)
	}
	if failed > 0 {
		return exitErr
	}
	return exitOK
}

// resolveBynPaths expands trust inputs into a deduped list of .byn file paths.
// A directory input resolves to <dir>/.byn; with recursive, each directory is
// walked for every .byn under it. A file (or unstattable) input is taken as-is.
func resolveBynPaths(inputs []string, recursive bool) []string {
	if len(inputs) == 0 {
		inputs = []string{"."}
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, in := range inputs {
		info, err := os.Stat(in)
		switch {
		case err != nil:
			add(in) // let the daemon report the per-file read error
		case recursive && info.IsDir():
			_ = filepath.WalkDir(in, func(path string, d fs.DirEntry, werr error) error {
				if werr == nil && !d.IsDir() && d.Name() == ".byn" {
					add(path)
				}
				return nil
			})
		case info.IsDir():
			add(filepath.Join(in, ".byn"))
		default:
			add(in)
		}
	}
	return out
}

// runUntrust revokes trust for one or many .byn files. Like trust, it accepts
// positional paths, --paths (comma-separated), and --recursive (walk dirs); a
// directory resolves to <dir>/.byn. Revoking needs no password (it is fail-safe
// — an untrusted .byn is refused by exec) and the trust store is global, so no
// per-vault grouping is needed.
func runUntrust(args []string, _ cliScope) int {
	fs := flag.NewFlagSet("untrust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pathsCSV := fs.String("paths", "", "comma-separated .byn files or directories to untrust")
	recursive := fs.Bool("recursive", false, "walk each given directory for every .byn under it")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	inputs := append([]string{}, fs.Args()...)
	for _, p := range strings.Split(*pathsCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			inputs = append(inputs, p)
		}
	}
	paths := resolveBynPaths(inputs, *recursive)
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "%s no .byn files to untrust\n", boldRed("Error:"))
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}

	client := newClient(dir)
	multi := len(paths) > 1
	removed, absent := 0, 0
	for _, p := range paths {
		canon := trust.Canonicalize(p)
		var resp ipc.TrustRemoveResp
		if cerr := client.Call(ipc.OpTrustRemove, ipc.TrustRemoveReq{Path: canon}, &resp); cerr != nil {
			return handleCallError(cerr)
		}
		switch {
		case resp.Removed && multi:
			removed++
			fmt.Fprintf(os.Stderr, "  %s %s\n", cyan("-"), canon)
		case resp.Removed:
			removed++
			hintf("Untrusted %s.", canon)
		case multi:
			absent++
			fmt.Fprintf(os.Stderr, "  %s %s (was not trusted)\n", dim("."), canon)
		default:
			absent++
			fmt.Fprintf(os.Stderr, "(%s was not trusted)\n", canon)
		}
	}
	if multi {
		suffix := ""
		if absent > 0 {
			suffix = fmt.Sprintf(" (%d were not trusted)", absent)
		}
		hintf("Untrusted %d .byn file(s)%s.", removed, suffix)
	}
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
  byn trust [PATH...]           Trust one or more .byn files (default: ./.byn).
                                A directory resolves to <dir>/.byn.
  byn trust --paths "a,b,c"     Trust a comma-separated list of files/dirs
  byn trust --recursive [DIR]   Walk directories (default: .) for every .byn
  byn trust [...] --password-stdin
                                Read the master password from stdin (one vault)
  byn trust list [--json]       List currently trusted paths
  byn untrust [PATH...]         Revoke trust (default: ./.byn); also takes
                                --paths "a,b,c" and --recursive

Bulk trust groups files by their target vault and asks each vault's password
once (so a monorepo's .byn files across vaults need only one prompt per vault).`)
}
