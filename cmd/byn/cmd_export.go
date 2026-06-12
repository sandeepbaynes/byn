// `byn export` — dump all env-var entries in the active scope to
// .env / .yaml / .json on stdout (or --output PATH).
//
// Security note: this materializes every value of the scope as
// plaintext on stdout. Use --to-clipboard if available later. For now
// the user is responsible for the destination — same caveat as
// `byn get` writing to stdout.
//
// When [security] per_action_auth is on, each get requires a master
// password. Use --password-stdin to read it once and reuse for every
// entry. Without --password-stdin, on the first auth_required the CLI
// prompts once interactively and reuses the same password for all
// subsequent gets. Each entry re-verifies the password (Argon2id), so
// NU-3 sessions are now in place: newClient loads the session token from
// disk and threads it through every Get, so with an active session zero
// auth prompts fire. The per-entry password path is retained for the
// sessionless / per_action_auth case.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func runExport(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "env", "output format: env|yaml|json")
	output := fs.String("output", "-", "output path or '-' for stdout")
	pwStdin := fs.Bool("password-stdin", false,
		"if [security] per_action_auth is on, read the master password from stdin (non-interactive)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	client := newClient(dir, scope.Vault)

	scopeIPC := scope.ToIPC()
	var lresp ipc.ListResp
	if err := client.Call(ipc.OpList, ipc.ListReq{Scope: scopeIPC}, &lresp); err != nil {
		return handleCallError(err)
	}

	// Fetch each entry's value, handling per_action_auth transparently.
	// Strategy: try the first get with no password; on auth_required, read the
	// password once and reuse it for the remainder of the loop.
	var pw []byte       // nil until first auth_required
	var wipePw func()   // zeroes pw on return
	pwAcquired := false // true once we've read the password

	defer func() {
		if wipePw != nil {
			wipePw()
		}
	}()

	entries := make(map[string]string, len(lresp.Secrets))
	keys := make([]string, 0, len(lresp.Secrets))
	for _, meta := range lresp.Secrets {
		var got ipc.GetResp
		err := client.Call(ipc.OpGet, ipc.GetReq{Scope: scopeIPC, Name: meta.Name, Password: pw}, &got)
		if err != nil && isAuthRequiredErr(err) && !pwAcquired {
			// First auth_required: acquire the password once.
			leadIn := yellow("Authorization required.") + dim(" [security] per_action_auth is on.")
			var perr error
			pw, wipePw, perr = authorizingPasswordWithLeadIn(*pwStdin, leadIn)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), perr)
				return exitErr
			}
			pwAcquired = true
			// Retry this entry with the now-known password.
			err = client.Call(ipc.OpGet, ipc.GetReq{Scope: scopeIPC, Name: meta.Name, Password: pw}, &got)
		}
		if err != nil {
			return handleCallError(err)
		}
		entries[meta.Name] = string(got.Value)
		keys = append(keys, meta.Name)
		zero(got.Value)
	}

	// Zero the password buffer once all entries are fetched.
	if wipePw != nil {
		wipePw()
		wipePw = nil
	}

	sort.Strings(keys)

	var rendered string
	switch *format {
	case "env", "dotenv":
		rendered = renderDotenv(keys, entries)
	case "yaml", "yml":
		bs, err := yaml.Marshal(entries)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		rendered = string(bs)
	case "json":
		bs, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		rendered = string(bs) + "\n"
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported format %q (want env|yaml|json)\n", *format)
		return exitErr
	}

	if *output == "-" {
		fmt.Print(rendered)
		return exitOK
	}
	if err := os.WriteFile(*output, []byte(rendered), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", *output, err)
		return exitErr
	}
	hintf("Exported %d entries to %s.", len(keys), *output)
	return exitOK
}

func renderDotenv(keys []string, m map[string]string) string {
	var b strings.Builder
	for _, k := range keys {
		v := m[k]
		needsQuote := strings.ContainsAny(v, " \t\n\"#=")
		fmt.Fprintf(&b, "%s=", k)
		if needsQuote {
			esc := strings.ReplaceAll(v, `\`, `\\`)
			esc = strings.ReplaceAll(esc, `"`, `\"`)
			esc = strings.ReplaceAll(esc, "\n", `\n`)
			fmt.Fprintf(&b, "\"%s\"", esc)
		} else {
			b.WriteString(v)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
