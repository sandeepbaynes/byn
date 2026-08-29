package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/term"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runInit creates a fresh vault. Prompts for the password twice
// unless --password-stdin is set (in which case the value is read raw
// from stdin and used without confirmation — caller's responsibility
// to not make a typo). If scope.Vault is non-empty, that vault is
// created instead of "default".
func runInit(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read password from stdin (no prompt, no confirmation)")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	var pw []byte
	if *pwStdin {
		pw, err = readPasswordStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer zero(pw)
	} else {
		// secmem-backed prompt: password is mlocked from prompt
		// through use, then wiped.
		pwBuf, err := auth.PromptStdinSecure("New master password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer pwBuf.Wipe()
		pw2Buf, err := auth.PromptStdinSecure("Confirm master password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer pw2Buf.Wipe()
		if !bytes.Equal(pwBuf.Bytes(), pw2Buf.Bytes()) {
			fmt.Fprintln(os.Stderr, "Error: passwords do not match")
			return exitErr
		}
		pw = pwBuf.Bytes()
	}
	if len(pw) < 8 {
		fmt.Fprintln(os.Stderr, "Error: password must be at least 8 characters")
		return exitErr
	}

	c := newClient(dir, "")
	err = c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: scope.Vault, Password: pw}, &ipc.VaultInitResp{})
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	vaultName := scope.Vault
	if vaultName == "" {
		vaultName = "default"
	}
	fmt.Printf("Vault %q created. Run `byn unlock` to start using it.\n", vaultName)
	return exitOK
}

func runUnlock(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read password from stdin (no prompt)")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	var pw []byte
	if *pwStdin {
		pw, err = readPasswordStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer zero(pw)
	} else {
		pwBuf, err := auth.PromptStdinSecure("Master password: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitErr
		}
		defer pwBuf.Wipe()
		pw = pwBuf.Bytes()
	}

	c := newClient(dir, scope.Vault)
	var resp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock,
		ipc.VaultUnlockReq{Name: scope.Vault, Password: pw}, &resp, c.Session)
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	if len(tok) > 0 {
		vaultKey := vaultSessionKey(scope.Vault)
		dev := ttyRdev()
		if dev != 0 {
			if serr := saveSessionTokenWithDev(sessionStoreDir(dir), dev, vaultKey, tok); serr != nil {
				// Non-fatal: vault is already unlocked; session file is convenience only.
				fmt.Fprintf(os.Stderr, "warning: could not save session token: %v\n", serr)
			} else {
				hintf("vault unlocked — session active for this terminal")
			}
		} else {
			hintf("vault unlocked")
		}
	}
	return exitOK
}

// readPasswordStdin reads stdin until EOF, strips a single trailing
// newline, and returns the result. Intended for piped/scripted use
// where the password isn't typed at a terminal.
func readPasswordStdin() ([]byte, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if n := len(data); n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
	}
	return data, nil
}

// readFirstLineStdin reads exactly the first line from stdin (up to and
// including the newline terminator) and returns the content WITHOUT the
// trailing newline. The remainder of stdin (after the newline) is left
// intact for subsequent reads. If stdin ends before a newline is found,
// all of stdin is returned.
//
// This is used by runPut to implement the --password-stdin contract:
//
//	{ echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin
//
// Line 1 = master password (consumed here), remainder = secret value.
func readFirstLineStdin() ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read stdin: %w", err)
		}
	}
	return line, nil
}

func runLock(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "lock every unlocked vault")
	sessionOnly := fs.Bool("session", false, "end this terminal's session only (does not lock the vault)")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	if *sessionOnly {
		// End only this terminal's session; leave the vault unlocked.
		vaultKey := vaultSessionKey(scope.Vault)
		if rc := handleCallError(newClient(dir, vaultKey).Call(
			ipc.OpSessionEnd, ipc.SessionEndReq{}, &ipc.SessionEndResp{})); rc != exitOK {
			return rc
		}
		deleteSessionToken(sessionStoreDir(dir), vaultKey)
		hintf("session ended for this terminal — vault remains unlocked")
		return exitOK
	}

	name := scope.Vault
	if *all {
		name = "*" // daemon locks every unlocked vault
	}
	var resp ipc.VaultLockResp
	if rc := handleCallError(newClient(dir, scope.Vault).Call(ipc.OpVaultLock,
		ipc.VaultLockReq{Name: name}, &resp)); rc != exitOK {
		return rc
	}
	if *all {
		deleteAllSessionTokens(sessionStoreDir(dir))
		hintf("Locked %d vault(s).", resp.Locked)
	} else {
		vaultKey := vaultSessionKey(scope.Vault)
		deleteSessionToken(sessionStoreDir(dir), vaultKey)
	}
	return exitOK
}

func runPut(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("put", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	createOnly := fs.Bool("create-only", false, "fail if name already exists")
	jsonOut := fs.Bool("json", false, "emit {stored,created,unattended} JSON instead of prose")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	switch {
	case fs.NArg() == 0:
		fmt.Fprintln(os.Stderr, "Usage: byn put <name>   (value is read from stdin)")
		return exitErr
	case fs.NArg() > 1:
		fmt.Fprintf(os.Stderr, "%s %s\n",
			boldRed("Error:"),
			red("That value is now in your shell history."))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, dim("Command-line arguments to any process are saved by your shell"))
		fmt.Fprintln(os.Stderr, dim("(~/.zsh_history, ~/.bash_history), visible to `ps aux` while the"))
		fmt.Fprintln(os.Stderr, dim("process runs, and may be recorded in OS audit logs. A secret on"))
		fmt.Fprintln(os.Stderr, dim("the command line is no longer a secret — treat the value you just"))
		fmt.Fprintln(os.Stderr, dim("typed as exposed and rotate it before storing for real."))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s read from a file (only the filename ends up in shell history):\n",
			bold(yellow("Recommended —")))
		fmt.Fprintf(os.Stderr, "  %s\n", cyan(fmt.Sprintf("byn put %s < secret.txt", fs.Arg(0))))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, bold(yellow("Other safe options:")))
		fmt.Fprintf(os.Stderr, "  %s  %s\n",
			cyan(fmt.Sprintf("pbpaste | byn put %s", fs.Arg(0))),
			dim("# paste from clipboard (macOS)"))
		fmt.Fprintf(os.Stderr, "  %s  %s\n",
			cyan(fmt.Sprintf("echo -n \"$VAR\" | byn put %s", fs.Arg(0))),
			dim("# env var (shell expands at runtime, $VAR is what hits history)"))
		return exitErr
	}
	name := fs.Arg(0)

	// When --password-stdin is set, the FIRST LINE of stdin is the master
	// password and the REMAINDER (after the first newline) is the secret
	// value. We pre-read the password line here — before readSecretValue
	// drains the rest of stdin — so both pieces are captured up front.
	//
	// The first line is ALWAYS consumed when --password-stdin is set, even
	// if the daemon never asks for authorization (the value still comes from
	// the remainder). This makes the contract deterministic for callers:
	//
	//   { echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin
	//
	// Fail fast when --password-stdin is set but stdin is a TTY: reading
	// from a terminal would echo the password to the screen before
	// readSecretValue's own TTY check fires, giving no indication that
	// echoing is happening.
	var prereadPw []byte
	if *pwStdin {
		if stdinIsTTY() {
			fmt.Fprintln(os.Stderr, "Error: --password-stdin requires piped stdin (stdin is a terminal)")
			return exitErr
		}
		var perr error
		prereadPw, perr = readFirstLineStdin()
		if perr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", perr)
			return exitErr
		}
		defer zero(prereadPw)
	}

	value, err := readSecretValue()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	defer zero(value)

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}

	// Storing a first secret should not require knowing a vault has to exist
	// first; if it does not, the retry helper creates it and runs this again.
	setFirstRunTarget(newClient(dir, scope.Vault), scope.Vault)

	// putCall issues the IPC put with the given password (nil = no auth yet).
	var putResp ipc.PutResp
	var putErr error
	putCall := func(pw []byte) error {
		putResp = ipc.PutResp{}
		putErr = newClient(dir, scope.Vault).Call(ipc.OpPut,
			ipc.PutReq{Scope: scope.ToIPC(), Name: name, Value: value, CreateOnly: *createOnly, Password: pw},
			&putResp)
		return putErr
	}

	var rc int
	if *pwStdin {
		// A supplied password is sent with the write itself, not held back as
		// a fallback for a refusal.
		//
		// It used to try unattended first and authenticate only if that was
		// refused, which quietly did the wrong thing whenever the unattended
		// path happened to be open: the write went under the scope's authored
		// key — machine-protected, and still owned by the agent whose session
		// created the value — while the person at the keyboard had just proved
		// who they were in order to take it back. They were told nothing, and
		// the agent could still read, replace and delete what they had written.
		//
		// Supplying a password is the caller saying which key this belongs
		// under. On a locked vault that now ends in "byn unlock, then retry"
		// where it used to silently succeed, which is the honest answer: byn
		// cannot seal under a master key it does not hold.
		if len(prereadPw) == 0 {
			rc = handleCallError(putCall(nil))
		} else {
			rc = handleCallError(putCall(prereadPw))
		}
	} else {
		rc = mutateWithAuthRetry(false, false, false, nil, putCall)
	}

	if rc != exitOK && *jsonOut {
		emitCallErrorJSON(os.Stdout, map[string]any{"name": name}, putErr, rc)
		return rc
	}
	if rc == exitOK {
		switch {
		case *jsonOut:
			obj := map[string]any{
				"stored": name, "scope": scope.String(),
				"created": putResp.Created, "unattended": putResp.Unattended,
			}
			if putResp.Unattended {
				// The prose says how long this stays readable; the JSON has to
				// carry the same fact, or a caller reading only the JSON does
				// not know it holds something with a lifetime.
				obj["lifetime"] = "session"
				obj["readable_while"] = "this agent's session lives and nobody else writes it"
			}
			out, merr := json.Marshal(obj)
			if merr == nil {
				_, _ = fmt.Fprintln(os.Stdout, string(out))
			}
		case putResp.Unattended:
			// Not a hint: hints are suppressed when nothing is watching, which
			// is exactly when this matters. A caller that stored a value it can
			// only read back for as long as its own session lives needs to be
			// told so, at the moment it happens.
			fmt.Fprintf(os.Stderr, "%s stored %s (unattended — readable by this agent while its session lives)\n",
				yellow("note:"), name)
		default:
			hintf("Stored %q in %s.", name, scope)
		}
	}
	return rc
}

func runGet(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit {name,value} JSON instead of raw")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn get <name>")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	name := fs.Arg(0)
	var resp ipc.GetResp
	var lastErr error
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, false, nil, func(pw []byte) error {
		lastErr = newClient(dir, scope.Vault).Call(ipc.OpGet, ipc.GetReq{Scope: scope.ToIPC(), Name: name, Password: pw}, &resp)
		return lastErr
	})
	if rc != exitOK {
		// --json means machine output for the refusal as well as the value. A
		// caller that has to parse an English refusal to learn it was refused is
		// back where the id-in-prose problem started.
		if *jsonOut {
			emitGetErrorJSON(os.Stdout, name, lastErr, rc)
		}
		return rc
	}
	if *jsonOut {
		out, _ := json.Marshal(struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}{Name: name, Value: string(resp.Value)})
		fmt.Println(string(out))
		return exitOK
	}
	// Write the value as-is to stdout. When stdout is piped or
	// redirected we emit the raw bytes only — appending a newline
	// would corrupt key files (`byn get tls-key > server.key`)
	// and command substitution (`$(byn get aws-profile)`). When
	// stdout is a terminal we add a single trailing newline if the
	// value doesn't already end with one, so the next shell prompt
	// doesn't run onto the value (and zsh doesn't display `%`).
	if _, werr := os.Stdout.Write(resp.Value); werr != nil {
		fmt.Fprintf(os.Stderr, "Error: write stdout: %v\n", werr)
		return exitErr
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if len(resp.Value) == 0 || resp.Value[len(resp.Value)-1] != '\n' {
			fmt.Println()
		}
	}
	return exitOK
}

// runList lists secret NAMES in the active scope (never values), so it works
// while the vault is locked. With an optional NAME or GLOB argument it acts
// like grep: prints only the matching names and exits 0 when at least one
// matches, exits 1 (printing nothing) when none do. This lets an agent test
// "does VAR exist?" via the exit code without ever calling `get`.
//
//	byn ls                 list every name in the scope
//	byn ls SQL_POOL_MAX     print it (exit 0) if it exists, else nothing (exit 1)
//	byn ls 'SQL*'          list names starting with SQL (quote to dodge the shell)
func runList(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "output as JSON array")
	long := fs.Bool("long", false, "annotate each name (marks values stored with no password behind the call)")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}

	var pattern string
	switch fs.NArg() {
	case 0:
	case 1:
		pattern = fs.Arg(0)
		// Validate the glob up front so a malformed pattern is a clear error
		// rather than a silent no-match.
		if _, err := path.Match(pattern, ""); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid pattern %q: %v\n", pattern, err)
			return exitErr
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: byn ls [NAME|GLOB]")
		return exitErr
	}

	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.ListResp
	err = newClient(dir, scope.Vault).Call(ipc.OpList, ipc.ListReq{Scope: scope.ToIPC()}, &resp)
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}

	secrets := resp.Secrets
	if pattern != "" {
		matched := secrets[:0]
		for _, s := range secrets {
			if ok, _ := path.Match(pattern, s.Name); ok {
				matched = append(matched, s)
			}
		}
		secrets = matched
	}

	if *jsonOut {
		out, _ := json.MarshalIndent(secrets, "", "  ")
		fmt.Println(string(out))
		if pattern != "" && len(secrets) == 0 {
			return exitErr // grep-style: no match
		}
		return exitOK
	}

	if pattern != "" {
		// Matches only — no "(no secrets stored)" noise. Exit 1 on no match
		// so `byn ls VAR && …` works as an existence check.
		for _, s := range secrets {
			fmt.Println(s.Name)
		}
		if len(secrets) == 0 {
			return exitErr
		}
		return exitOK
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "(no secrets stored)")
		return exitOK
	}
	for _, s := range secrets {
		if *long {
			// The per-name marker lives here and nowhere else. The plain list
			// is a pure existence probe that callers pipe and test with
			// `byn list NAME && …`; annotating it would break them, which is
			// why this is a separate flag rather than a nicer default.
			mark := ""
			if s.Unattended {
				mark = "  " + yellow("(unattended value)")
			}
			fmt.Println(s.Name + mark)
			continue
		}
		fmt.Println(s.Name)
	}
	// Which of these appeared with nobody behind the call.
	//
	// On stderr, and never in the pattern form: stdout here is a names-only
	// list that callers pipe and use as an existence probe, and decorating it
	// would break them. --json carries the same fact as a field.
	var unattended []string
	for _, s := range secrets {
		if s.Unattended {
			unattended = append(unattended, s.Name)
		}
	}
	if len(unattended) > 0 {
		fmt.Fprintf(os.Stderr, "%s %d value(s) here were stored with no password behind the call: %s\n",
			yellow("note:"), len(unattended), strings.Join(unattended, ", "))
		fmt.Fprintf(os.Stderr, "      byn cannot tell one an agent invented from one you provisioned.\n")
	}
	return exitOK
}

func runDelete(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	jsonOut := fs.Bool("json", false, "emit {deleted,scope} JSON instead of prose")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: byn delete <name>")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	name := fs.Arg(0)
	var lastErr error
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, true, nil, func(pw []byte) error {
		lastErr = newClient(dir, scope.Vault).Call(ipc.OpDelete,
			ipc.DeleteReq{Scope: scope.ToIPC(), Name: name, Password: pw}, &ipc.DeleteResp{})
		return lastErr
	})
	if *jsonOut {
		// Both outcomes as data, for the same reason every other --json path
		// gives: a caller should not have to read an English sentence to learn
		// whether the thing it asked for happened.
		if rc == exitOK {
			emitJSONLine(os.Stdout, map[string]any{"deleted": name, "scope": scope.String()})
		} else {
			emitCallErrorJSON(os.Stdout, map[string]any{"name": name}, lastErr, rc)
		}
		return rc
	}
	if rc == exitOK {
		hintf("Deleted %q from %s.", name, scope)
	}
	return rc
}

func runRename(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("rename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := parseFlags(fs, args); err != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "Usage: byn rename <old> <new>")
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	old, neu := fs.Arg(0), fs.Arg(1)
	rc := mutateWithAuthRetry(*pwStdin, false, false, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpRename,
			ipc.RenameReq{Scope: scope.ToIPC(), OldName: old, NewName: neu, Password: pw},
			&ipc.RenameResp{})
	})
	if rc == exitOK {
		hintf("Renamed %q → %q in %s.", old, neu, scope)
	}
	return rc
}

// readSecretValue reads the value to store from stdin. If stdin is a
// terminal it errors out (we don't want users to accidentally type a
// secret into an echoing prompt); the value must be piped or
// redirected.
func readSecretValue() ([]byte, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat stdin: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return nil, errors.New("stdin is a terminal — pipe or redirect the value (e.g. `echo s3cr3t | byn put k`)")
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	// Strip a single trailing newline — convenient for `echo foo | byn put`.
	if n := len(data); n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
	}
	return data, nil
}

// emitGetErrorJSON reports a refused read as data.
func emitGetErrorJSON(w *os.File, name string, callErr error, exitCode int) {
	emitCallErrorJSON(w, map[string]any{"name": name}, callErr, exitCode)
}

// emitCallErrorJSON reports any refused mutation as data, in one shape.
//
// One renderer rather than one per command: this defect has been found three
// times in three places — the approval id readable only from prose, then get,
// then delete — because each command grew its own error path. Fields common to
// every refusal live here so the next command cannot quietly omit them.
func emitCallErrorJSON(w *os.File, base map[string]any, callErr error, exitCode int) {
	obj := map[string]any{"status": "denied", "exit": exitCode}
	for k, v := range base {
		obj[k] = v
	}
	var em *ipc.ErrResponse
	if errors.As(callErr, &em) {
		obj["status"] = string(em.Code)
		obj["message"] = em.Message
		if em.Recover != "" {
			obj["recover"] = em.Recover
		}
		for k, v := range em.Details {
			obj[k] = v
		}
	}
	emitJSONLine(w, obj)
}

// emitJSONLine writes one object and a newline, or nothing if it cannot.
func emitJSONLine(w *os.File, obj map[string]any) {
	if b, err := json.Marshal(obj); err == nil {
		_, _ = fmt.Fprintln(w, string(b))
	}
}
