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
	if err := fs.Parse(args); err != nil {
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
	if err := fs.Parse(args); err != nil {
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
	if err := fs.Parse(args); err != nil {
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
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := fs.Parse(args); err != nil {
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

	// putCall issues the IPC put with the given password (nil = no auth yet).
	putCall := func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpPut,
			ipc.PutReq{Scope: scope.ToIPC(), Name: name, Value: value, CreateOnly: *createOnly, Password: pw},
			&ipc.PutResp{})
	}

	var rc int
	if *pwStdin {
		// Inline retry that uses prereadPw on the auth-required retry instead
		// of reading from stdin (which now points at the value remainder).
		// Only retry on CodeAuthRequired — CodeLocked is a dead end for put
		// because the vault key must be in memory.
		firstErr := putCall(nil)
		switch {
		case firstErr == nil:
			rc = exitOK
		case isAuthRequiredErr(firstErr):
			rc = handleCallError(putCall(prereadPw))
		default:
			rc = handleCallError(firstErr)
		}
	} else {
		rc = mutateWithAuthRetry(false, false, false, nil, putCall)
	}

	if rc == exitOK {
		hintf("Stored %q in %s.", name, scope)
	}
	return rc
}

func runGet(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit {name,value} JSON instead of raw")
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := fs.Parse(args); err != nil {
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
	rc := mutateWithAuthRetry(*pwStdin, *jsonOut, false, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpGet, ipc.GetReq{Scope: scope.ToIPC(), Name: name, Password: pw}, &resp)
	})
	if rc != exitOK {
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
	if err := fs.Parse(args); err != nil {
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
		fmt.Println(s.Name)
	}
	return exitOK
}

func runDelete(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "if the vault is locked, read the authorizing password from stdin")
	if err := fs.Parse(args); err != nil {
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
	rc := mutateWithAuthRetry(*pwStdin, false, true, nil, func(pw []byte) error {
		return newClient(dir, scope.Vault).Call(ipc.OpDelete,
			ipc.DeleteReq{Scope: scope.ToIPC(), Name: name, Password: pw}, &ipc.DeleteResp{})
	})
	if rc == exitOK {
		hintf("Deleted %q from %s.", name, scope)
	}
	return rc
}

func runRename(args []string, scope cliScope) int {
	fs := flag.NewFlagSet("rename", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pwStdin := fs.Bool("password-stdin", false, "read the authorizing password from stdin for non-interactive authorization")
	if err := fs.Parse(args); err != nil {
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
