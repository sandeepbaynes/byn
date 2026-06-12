// `byn import` — bulk-load key/value entries from .env / .yaml /
// .json into the active scope.
//
// Format detection is by extension first, then by sniffing content
// when the extension is missing or ambiguous (stdin form). Nested
// objects are flagged with a clear error — only flat key→string maps
// are accepted (an env var can't model a tree).
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

type importFormat int

const (
	fmtUnknown importFormat = iota
	fmtDotenv
	fmtYAML
	fmtJSON
)

func runImport(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "", "force format: env|yaml|json (default: by extension)")
	dryRun := fs.Bool("dry-run", false, "show what would be imported without writing")
	skipExisting := fs.Bool("skip-existing", false, "add-only: skip keys that already exist (default: merge — add+overwrite)")
	replace := fs.Bool("replace", false, "destructive: wipe every existing key in the scope before importing")
	yes := fs.Bool("yes", false, "skip the confirmation prompt for --replace")
	pwStdin := fs.Bool("password-stdin", false,
		"read the master password from stdin for non-interactive authorization")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	if *replace && *skipExisting {
		fmt.Fprintln(os.Stderr, "Error: --replace and --skip-existing are mutually exclusive")
		return exitErr
	}

	var (
		src    io.Reader
		srcTag string
		ext    string
	)
	switch {
	case fs.NArg() == 0 || fs.Arg(0) == "-":
		src = os.Stdin
		srcTag = "<stdin>"
	case fs.NArg() == 1:
		path := fs.Arg(0)
		f, err := os.Open(path) //nolint:gosec
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer func() { _ = f.Close() }()
		src = f
		srcTag = path
		ext = strings.ToLower(filepath.Ext(path))
	default:
		fmt.Fprintln(os.Stderr, "Usage: byn import [PATH | -] [--format env|yaml|json]")
		return exitErr
	}

	body, err := io.ReadAll(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", srcTag, err)
		return exitErr
	}

	fmtVal := pickFormat(*format, ext, body)
	if fmtVal == fmtUnknown {
		fmt.Fprintln(os.Stderr, "Error: cannot detect format. Pass --format=env|yaml|json.")
		return exitErr
	}

	entries, perr := parseImport(body, fmtVal)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", srcTag, perr)
		return exitErr
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "(no entries found in input)")
		return exitOK
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	client := newClient(dir, scope.Vault)
	scopeIPC := scope.ToIPC()

	// --replace: enumerate the existing entries in scope so we can
	// preview them in --dry-run, confirm before wiping, and report
	// counts. Non-replace runs skip this list call.
	var toWipe []ipc.SecretMeta
	if *replace {
		var listResp ipc.ListResp
		if err := client.Call(ipc.OpList, ipc.ListReq{Scope: scopeIPC}, &listResp); err != nil {
			return handleCallError(err)
		}
		// Only delete entries that actually live in this exact scope
		// (Source "scope"). Inherited entries from default come back
		// in List but belong to a different env; deleting them would
		// be surprising.
		for _, e := range listResp.Secrets {
			if e.Source == "scope" {
				toWipe = append(toWipe, e)
			}
		}
	}

	if *dryRun {
		fmt.Printf("Would import %d entries into %s:\n", len(entries), scope.String())
		if *replace {
			fmt.Printf("  delete (%d existing entries in scope):\n", len(toWipe))
			for _, e := range toWipe {
				fmt.Printf("    - %s\n", e.Name)
			}
			fmt.Printf("  add/overwrite (%d entries from input):\n", len(entries))
		}
		for _, e := range entries {
			fmt.Printf("    + %s = (%d bytes)\n", e.k, len(e.v))
		}
		return exitOK
	}

	// Shared auth state for both the wipe loop and the put loop.
	// Both loops are auth-gated. The password is read from stdin at most once
	// — whichever loop first hits auth_required acquires it, and the other
	// loop reuses the already-acquired bytes rather than trying to drain stdin
	// a second time (which would produce an empty read).
	var sharedPw []byte
	var sharedPwWipeFn func()
	sharedPwAcquired := false
	acquireSharedPw := func() error {
		if sharedPwAcquired {
			return nil
		}
		leadIn := yellow("Authorization required.") + dim(" Enter the master password to authorize.")
		var perr error
		sharedPw, sharedPwWipeFn, perr = authorizingPasswordWithLeadIn(*pwStdin, leadIn)
		if perr != nil {
			return perr
		}
		sharedPwAcquired = true
		return nil
	}
	defer func() {
		if sharedPwWipeFn != nil {
			sharedPwWipeFn()
		}
	}()

	if *replace {
		if !*yes {
			if !stdinIsTTY() {
				fmt.Fprintf(os.Stderr,
					"Error: --replace requires --yes in non-TTY/agent mode (would wipe %d entries from %s)\n",
					len(toWipe), scope.String())
				return exitErr
			}
			fmt.Fprintf(os.Stderr,
				"%s Wipe %d entries from %s and import %d new ones? [y/N]: ",
				boldRed("CONFIRM:"), len(toWipe), scope.String(), len(entries))
			var resp string
			_, _ = fmt.Fscanln(os.Stdin, &resp)
			if !strings.EqualFold(strings.TrimSpace(resp), "y") {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return exitErr
			}
		}
		// Wipe step. Best-effort — N round-trips today; can be
		// collapsed to one transactional daemon op if perf becomes a
		// concern.
		//
		// Delete is auth-gated (authorizeAction: session OR password).
		// On first auth_required we acquire the shared password once and
		// reuse it for every subsequent delete (and the put loop below).
		for _, e := range toWipe {
			err := client.Call(ipc.OpDelete,
				ipc.DeleteReq{Scope: scopeIPC, Name: e.Name, Password: sharedPw},
				&ipc.DeleteResp{})
			if err != nil && isAuthRequiredErr(err) {
				if aerr := acquireSharedPw(); aerr != nil {
					fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), aerr)
					return exitErr
				}
				// Retry this entry with the now-known password.
				err = client.Call(ipc.OpDelete,
					ipc.DeleteReq{Scope: scopeIPC, Name: e.Name, Password: sharedPw},
					&ipc.DeleteResp{})
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error deleting %q during wipe: %v\n", e.Name, err)
				return exitErr
			}
		}
	}

	// Put loop: add/overwrite entries from the import file.
	// Reuses sharedPw if already acquired by the wipe loop above; otherwise
	// acquires it on the first auth_required encountered here.
	created, updated, skipped := 0, 0, 0
	for _, e := range entries {
		req := ipc.PutReq{
			Scope:      scopeIPC,
			Name:       e.k,
			Value:      []byte(e.v),
			CreateOnly: *skipExisting,
			Password:   sharedPw,
		}
		err := client.Call(ipc.OpPut, req, &ipc.PutResp{})
		if err != nil && isAuthRequiredErr(err) {
			if aerr := acquireSharedPw(); aerr != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), aerr)
				return exitErr
			}
			// Retry this entry with the now-known password.
			req.Password = sharedPw
			err = client.Call(ipc.OpPut, req, &ipc.PutResp{})
		}
		if err != nil {
			if *skipExisting && isAlreadyExists(err) {
				skipped++
				continue
			}
			fmt.Fprintf(os.Stderr, "Error setting %q: %v\n", e.k, err)
			return exitErr
		}
		if *skipExisting {
			created++
		} else {
			updated++
		}
	}
	if *replace {
		hintf("Imported %d entries into %s (replaced %d existing).",
			created+updated, scope.String(), len(toWipe))
	} else {
		hintf("Imported %d entries into %s (created/updated=%d, skipped=%d).",
			created+updated, scope.String(), created+updated, skipped)
	}
	return exitOK
}

type kv struct{ k, v string }

func pickFormat(forced, ext string, body []byte) importFormat {
	switch forced {
	case "env", "dotenv":
		return fmtDotenv
	case "yaml", "yml":
		return fmtYAML
	case "json":
		return fmtJSON
	}
	switch ext {
	case ".env":
		return fmtDotenv
	case ".yaml", ".yml":
		return fmtYAML
	case ".json":
		return fmtJSON
	}
	trimmed := strings.TrimLeftFunc(string(body), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if strings.HasPrefix(trimmed, "{") {
		return fmtJSON
	}
	return fmtUnknown
}

func parseImport(body []byte, f importFormat) ([]kv, error) {
	switch f {
	case fmtDotenv:
		return parseDotenv(body)
	case fmtJSON:
		return parseFlatJSON(body)
	case fmtYAML:
		return parseFlatYAML(body)
	}
	return nil, errors.New("unsupported format")
}

func parseDotenv(body []byte) ([]kv, error) {
	var out []kv
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "export ") {
			raw = strings.TrimPrefix(raw, "export ")
			raw = strings.TrimLeft(raw, " \t")
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: missing '='", lineNo)
		}
		k := strings.TrimSpace(raw[:eq])
		v := raw[eq+1:]
		if k == "" {
			return nil, fmt.Errorf("line %d: empty key", lineNo)
		}
		// Strip inline comment if value is unquoted.
		if !strings.HasPrefix(v, "\"") && !strings.HasPrefix(v, "'") {
			if hash := strings.Index(v, " #"); hash >= 0 {
				v = v[:hash]
			}
			v = strings.TrimSpace(v)
		} else {
			quote := v[0]
			v = v[1:]
			end := strings.IndexByte(v, quote)
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated quoted value", lineNo)
			}
			v = v[:end]
			if quote == '"' {
				v = strings.ReplaceAll(v, `\n`, "\n")
				v = strings.ReplaceAll(v, `\t`, "\t")
				v = strings.ReplaceAll(v, `\"`, `"`)
				v = strings.ReplaceAll(v, `\\`, `\`)
			}
		}
		out = append(out, kv{k: k, v: v})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseFlatJSON(body []byte) ([]kv, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return coerceFlat(raw)
}

func parseFlatYAML(body []byte) ([]kv, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return coerceFlat(raw)
}

func isAlreadyExists(err error) bool {
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		return er.Code == ipc.CodeAlreadyExists
	}
	return false
}

func coerceFlat(m map[string]any) ([]kv, error) {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		switch tv := v.(type) {
		case string:
			out = append(out, kv{k: k, v: tv})
		case bool:
			out = append(out, kv{k: k, v: fmt.Sprintf("%t", tv)})
		case int:
			out = append(out, kv{k: k, v: fmt.Sprintf("%d", tv)})
		case int64:
			out = append(out, kv{k: k, v: fmt.Sprintf("%d", tv)})
		case float64:
			out = append(out, kv{k: k, v: fmt.Sprintf("%v", tv)})
		case nil:
			out = append(out, kv{k: k, v: ""})
		default:
			return nil, fmt.Errorf("key %q: nested or unsupported type %T — only flat string/scalar maps are accepted", k, v)
		}
	}
	return out, nil
}
