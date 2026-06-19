package main

// Per-command help blobs, AWS-CLI style (NAME / SYNOPSIS / DESCRIPTION
// / OPTIONS / EXAMPLES / EXIT STATUS / SEE ALSO).
//
// Update man/byn.1 in lockstep when you add or change anything user-
// visible here — the man page and these strings are dual sources of truth.

// helpFor returns the help text for the named command (or alias).
// Returns "" if no help is registered.
func helpFor(name string) string {
	if h, ok := commandHelp[name]; ok {
		return h
	}
	// Aliases route to the canonical name's help.
	switch name {
	case "cat":
		return commandHelp["get"]
	case "ls":
		return commandHelp["list"]
	case "rm":
		return commandHelp["delete"]
	case "mv":
		return commandHelp["rename"]
	case "view":
		return commandHelp["edit"]
	case "start", "stop", "restart", "reload":
		return commandHelp["daemon"]
	}
	return ""
}

var commandHelp = map[string]string{
	"init": `NAME
       byn-init - create a new vault

SYNOPSIS
       byn init [--password-stdin]

DESCRIPTION
       Initializes a new byn vault under the data directory. The
       vault key is freshly generated (32 random bytes), wrapped with
       Argon2id of the master password, and persisted to disk. A
       default project ("default") and its default env are created
       automatically.

       After init, run "byn unlock" to load the vault key into the
       daemon so put/get/list operations work.

       The vault is created under the data directory at:
           <data-dir>/vaults/default/
       Files written:
           - vault.db        SQLite database (mode 0600)
           - wrapped.key     Argon2id-wrapped vault key (mode 0600)
           - meta.json       UUID + wrapped-key fingerprint (mode 0600)

OPTIONS
       --password-stdin
           Read the master password from stdin instead of prompting at
           the terminal. No confirmation step is performed; the caller
           is responsible for not mistyping. Useful for automation.

CHOOSING THE VAULT
       Multi-vault is shipped. --vault NAME (or BYN_VAULT) targets
       any vault on init / unlock / lock and every data-plane command:

           $ byn --vault work   init
           $ byn --vault work   unlock
           $ byn --vault work   put DB_URL  < /dev/null
           $ byn vault list

       Each vault lives under <data-dir>/vaults/<name>/ with its own
       wrapped key, SQLite DB, audit log, and meta.json.

THE DATA DIRECTORY
       byn's state lives at a fixed per-OS system path (the data
       directory) — there is no runtime override. To keep credentials
       separate, use multiple vaults (--vault NAME), not multiple data
       directories.

EXAMPLES
       Interactive (prompts twice for confirmation):
           $ byn init

       Scripted:
           $ echo "$MASTER_PW" | byn init --password-stdin

       Separate vault per org (today's multi-vault):
           $ byn --vault acme init
           $ byn --vault acme unlock

EXIT STATUS
       0    Vault created successfully.
       1    Bad input (password too short, mismatched confirmation,
            etc.).
       2    Daemon unreachable. Start it with: byn start
       3    Daemon error (already initialized, internal failure).

SEE ALSO
       byn(1), byn-unlock(1), byn-daemon(1)
`,

	"unlock": `NAME
       byn-unlock - authorize value access for THIS terminal's session (not global)

SYNOPSIS
       byn unlock [--password-stdin]

DESCRIPTION
       Prompts for the master password and authorizes value access
       (get / put / update / delete) for THIS terminal's session ONLY —
       it is NOT a global unlock. A per-terminal session token (bound to
       this TTY + UID) is saved to disk so subsequent commands in the
       SAME terminal skip re-prompting; other terminals, scripts, the
       portal, and background agents each authorize separately — one
       session never grants another. Run "byn lock --session" to clear
       this terminal's token without locking the vault for other callers.

       It does NOT affect "byn exec": a trusted .byn authorizes exec via
       its own [exec] actions + per-action auth, independent of the
       unlock/session state. (Internally the daemon also unwraps the
       vault key into memory, but value access still requires a valid
       session.)

       Failed unlock attempts trigger exponential backoff. The state is
       persisted across daemon restarts so killing the daemon does not
       reset the rate limit.

       The same error code is returned for "wrong password" and "no
       vault exists" to prevent an attacker from probing whether a
       vault is present.

OPTIONS
       --password-stdin
           Read the master password from stdin instead of prompting.

EXAMPLES
       Interactive:
           $ byn unlock

       Scripted (avoid leaving password in shell history):
           $ echo "$MASTER_PW" | byn unlock --password-stdin

EXIT STATUS
       0    Vault unlocked.
       1    Could not read password (no TTY, etc.).
       2    Daemon unreachable.
       3    Wrong password OR no vault initialized.

SEE ALSO
       byn(1), byn-init(1), byn-lock(1)
`,

	"lock": `NAME
       byn-lock - lock the vault by clearing the in-memory key

SYNOPSIS
       byn lock [--session]

DESCRIPTION
       Asks the daemon to zero the in-memory vault key. Subsequent
       value reads/writes will return a "vault is locked" error until
       the vault is unlocked again.

       Locking does NOT stop the daemon. The metadata index remains
       browseable; only value reads require unlock.

       With --session, only the CLI session token for the current
       terminal is revoked without locking the vault for other callers
       (useful when leaving a shared machine while keeping the vault
       available to other terminals or the portal).

OPTIONS
       --session
           Revoke the CLI session for the current terminal only;
           do not lock the vault.

EXAMPLES
       Lock vault for all callers:
           $ byn lock

       Revoke only this terminal's session:
           $ byn lock --session

EXIT STATUS
       0    Vault locked (or was already locked).
       2    Daemon unreachable.

SEE ALSO
       byn(1), byn-unlock(1)
`,

	"put": `NAME
       byn-put - store a secret

SYNOPSIS
       byn put [--create-only] [--password-stdin] NAME

DESCRIPTION
       Stores or updates a secret called NAME. The secret value is
       read from stdin — never the command line — so it does not show
       up in argv, ps output, shell history, or audit logs.

       Existing secrets are upserted by default. Use --create-only to
       refuse overwrites.

       Requires an unlocked vault.

       Overwriting an existing secret requires the master password when
       no session is present. The CLI prompts interactively; scripts
       should use --password-stdin. New secrets (with --create-only or
       the first put of a name) do not require authorization.

OPTIONS
       --create-only
           Fail with "already exists" instead of overwriting an
           existing secret with the same name.

       --password-stdin
           If an overwrite requires authorization and no session is present,
           read the master password from stdin instead of prompting at the
           terminal. Useful for scripts and CI.

           Contract: the FIRST LINE of stdin is the master password;
           the REMAINDER (after the first newline) is the secret value.
           The first line is always consumed when --password-stdin is set,
           even if the daemon never asks for authorization. Example:

               $ { echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin

EXAMPLES
       From a pipe:
           $ echo -n "AKIA..." | byn put aws-access-key

       From a file:
           $ byn put tls-key < server.key

       From an env var (the literal value is NOT recorded in shell
       history; $VAR is what's in history):
           $ echo -n "$DB_PW" | byn put db-password

       From the clipboard on macOS:
           $ pbpaste | byn put github-token

       Refuse to overwrite an existing secret:
           $ echo -n "new" | byn put aws-access-key --create-only

       Authorize an overwrite non-interactively (no session, via stdin):
           $ { echo "$BYN_PW"; printf 'new-val'; } | byn put key --password-stdin

EXIT STATUS
       0    Stored.
       1    Bad input (no NAME, value passed via argv, vault locked
            with no recovery hint).
       2    Daemon unreachable.
       3    Daemon error: vault locked, already-exists with
            --create-only, invalid name.

SECURITY NOTES
       Passing the value via argv (e.g. "byn put my-key hello")
       is rejected with an explanation: the value would otherwise
       end up in shell history files, in "ps aux" while the process
       runs, and possibly in OS process accounting logs.

SEE ALSO
       byn(1), byn-get(1), byn-unlock(1)
`,

	"get": `NAME
       byn-get - print a secret's value to stdout

SYNOPSIS
       byn get [--json] [--password-stdin] NAME
       byn cat NAME

DESCRIPTION
       Decrypts the secret named NAME and writes its raw bytes to
       stdout. No trailing newline is added when stdout is piped or
       redirected, so the output is byte-exact — suitable for piping
       into another program, writing to a file, or capturing with
       command substitution.

       When stdout is a terminal, a single trailing newline is
       appended for readability (no orphaned "%" in zsh).

       Requires an unlocked vault.

       Get requires the master password when no session is present. The
       CLI prompts interactively; scripts should use --password-stdin.

OPTIONS
       --json
           Emit {"name":"...","value":"..."} JSON instead of the raw value.

       --password-stdin
           When no session is present, read the master password from stdin
           instead of prompting at the terminal. Useful for scripts and CI.

EXAMPLES
       Print the value:
           $ byn get aws-access-key
           AKIA...

       Write to a key file:
           $ byn get tls-key > server.key

       Use directly in another command:
           $ aws --profile "$(byn get aws-profile)" s3 ls

       Inspect non-ASCII byte content:
           $ byn get binary-blob | xxd | head

       Non-interactive get (sessionless, via stdin):
           $ echo "$MASTER_PW" | byn get my-secret --password-stdin

EXIT STATUS
       0    Value written to stdout.
       1    No NAME, or write to stdout failed.
       2    Daemon unreachable.
       3    Daemon error: vault locked, secret not found.

SEE ALSO
       byn(1), byn-put(1), byn-list(1)
`,

	"list": `NAME
       byn-list - list secret names

SYNOPSIS
       byn list [NAME|GLOB]
       byn ls [NAME|GLOB]

DESCRIPTION
       Prints the names of secrets in the active scope, one per line.
       Does NOT require unlock — the index is plaintext metadata; only
       values require unlock.

       With no argument it lists every name (and prints "(no secrets
       stored)" to stderr when the scope is empty).

       With a NAME or GLOB argument it behaves like grep: it prints only
       the matching names and exits 0 when at least one matches, or
       prints NOTHING and exits 1 when none do. The glob supports * and
       ? (quote it so the shell doesn't expand it first). This lets an
       agent test whether a variable exists via the exit code, without
       ever calling "get" (which would read and audit the value).

EXAMPLES
       List everything:
           $ byn ls

       Does a specific var exist? (exit 0 = yes, 1 = no, prints nothing
       extra):
           $ byn ls SQL_POOL_MAX --vault maison && echo present

       Every name starting with SQL:
           $ byn ls 'SQL*'

EXIT STATUS
       0    Listing succeeded (or, with a pattern, at least one match).
       1    A pattern was given and nothing matched (or bad usage).
       2    Daemon unreachable.

SEE ALSO
       byn(1), byn-get(1), byn-delete(1)
`,

	"delete": `NAME
       byn-delete - remove a secret from the vault

SYNOPSIS
       byn delete [--password-stdin] NAME
       byn rm NAME

DESCRIPTION
       Removes the named secret. Does NOT require unlock — the
       metadata-only operation can be performed while the vault is
       locked.

       Without versioning enabled, deletion is immediate and
       unrecoverable.

       When the vault is locked or no session is present, the master
       password is required to authorize the deletion. The CLI prompts
       interactively; scripts should use --password-stdin.

OPTIONS
       --password-stdin
           The non-interactive way to supply the master password —
           reads it from stdin instead of prompting at the terminal.
           Useful for scripts and CI when the vault is locked or
           no session is present.

EXAMPLES
       Delete an entry:
           $ byn delete tls-key

       Delete using the alias:
           $ byn rm old-token

       Delete while vault is locked (or sessionless):
           $ echo "$MASTER_PW" | byn delete tls-key --password-stdin

EXIT STATUS
       0    Deleted.
       1    No NAME given.
       2    Daemon unreachable.
       3    Daemon error: not found, invalid name.

SEE ALSO
       byn(1), byn-list(1)
`,

	"exec": `NAME
       byn-exec - run a command with vault env-vars injected

SYNOPSIS
       byn exec [--no-privsep] [--inspect[=TARGET]] -- COMMAND [ARGS...]   (direct form)
       byn exec [--no-privsep] [--inspect[=TARGET]] NAME [ARGS...]         (alias form)

DESCRIPTION
       Loads the .byn-allowlisted env-var entries from the active vault
       scope, injects them into a child process's environment, and runs
       the command. HOW it runs depends on the execution mode (see
       EXECUTION MODES): by default the child runs under privilege
       separation as the _byn-exec service user — so its injected
       secrets are hidden from your own 'ps -E' — born in your shell's
       process tree; with --no-privsep it runs in-process as you.

   EXECUTION MODES
       byn exec            (default — privilege-separated)
           The daemon authorizes the exec; the child runs as the
           _byn-exec service user, born in your shell's process tree.
           Its injected env is HIDDEN from same-user snooping (your own
           'ps -E' shows nothing). A trusted .byn with a matching
           [exec] action runs CREDENTIAL-FREE — no password, even with
           the vault locked. This is the mode for agents, CI, and
           autonomous/unattended runs.

       byn exec --no-privsep   (for HUMAN debugging)
           The child runs IN-PROCESS as YOU (byn execve's into it), so a
           launch-mode debugger (e.g. VS Code "launch") can attach — it
           shares your UID. (A debugger cannot attach across UIDs, the
           same kernel rule that hides a privsep child's env, so it can't
           attach to the _byn-exec child directly.) The cost: the child's
           injected env is then visible to any same-UID process ('ps -E'
           on macOS, /proc/<pid>/environ on Linux). So this mode REQUIRES
           the master password on EVERY run and a trusted .byn does NOT
           authorize it (no credential-free path here). That password gate
           is the safeguard: it stops a rogue agent or attacker from using
           --no-privsep to inject your secrets into an owner-UID process
           they could then read — a human can type the password, an
           unattended agent cannot.

       byn exec --inspect[=PORT] | --inspect PORT   (and --inspect-brk)
           Keeps privilege separation AND enables the Node inspector, so
           you can debug while the secrets stay hidden. byn sets
           NODE_OPTIONS so the child opens an inspector; your debugger
           ATTACHES over loopback TCP (which is UID-agnostic).
             - no PORT      byn picks the next FREE port (printed), so
                            concurrent debug sessions don't collide.
             - PORT given   used only if FREE; otherwise byn fails with a
                            clear message (not a buried EADDRINUSE).
                            Accepts 9230 or 127.0.0.1:9230, spaced or '='
                            (--inspect 9230 / --inspect=9230).
             - --inspect=0  EACH node process self-allocates a free port
                            (best for 'tsx watch' and other multi-process
                            runners; node prints each).
           --inspect-brk breaks on the first line. Point your editor at an
           "attach" target.

       Choosing: unattended/agent -> default privsep; interactive
       step-debugging with a launch config -> --no-privsep (you enter
       the password); debugging while keeping secrets hidden ->
       --inspect with an attach config.

   DIRECT FORM
       The "--" separator is required to disambiguate exec's own
       flags from the child command's flags. Anything after "--" is
       the child argv.

           $ byn exec -- python deploy.py
           $ byn exec -- aws s3 ls --human-readable

   ALIAS FORM
       When a trusted .byn is in scope (discovered by walking up from
       CWD), named entry points from its [aliases] table may be invoked
       by name:

           $ byn exec deploy          # runs whatever "deploy" expands to
           $ byn exec deploy --watch  # extra args appended (strict passthrough)

       The daemon expands the alias server-side: it looks up the alias
       value in the trusted record's [aliases] map, splits it on
       whitespace, and appends any extra args you supplied. The expanded
       argv is then subject to the same [exec] actions pattern matching
       as a direct exec. The daemon returns the canonical (expanded)
       argv to the CLI as ResolvedArgv.

       Example .byn [aliases] section:
           [aliases]
           deploy   = "kubectl apply -f deploy/"
           test     = "cargo test {{args}}"
           migrate  = "python manage.py migrate"

       Alias shadowing: if both an alias named "test" and a binary named
       "test" exist, 'byn exec test' runs the alias; 'byn exec -- test'
       runs the binary. The "--" always forces direct form.

       Alias not found: if the alias is not defined, the daemon returns
       an error with the available alias names (up to 8).

       Requires a trusted .byn in scope. Running 'byn exec ALIAS' from a
       directory with no .byn is a usage error.

   ACTIONS PATTERN MATCHING
       The [exec] actions list supports typed placeholders in addition to
       exact strings. Patterns let you pin commands while allowing
       variable arguments:

           actions = [
               "aws s3 cp {{path}} {{path}}",
               "kubectl get {{alnum}}",
               "pytest {{args}}",
           ]

       Placeholder types:
           {{uuid}}    UUID (any case, with or without dashes)
           {{int}}     integer (optional leading minus, digits only)
           {{alnum}}   alphanumeric string (letters and digits)
           {{str}}     any single non-empty token
           {{path}}    any token without a NUL byte (syntactic; no FS check)
           {{url}}     HTTP(S) URL
           {{re:…}}    custom regular expression (anchored per token)
           {{args}}    zero or more remaining tokens (tail wildcard;
                       must be the last token in the pattern)

       Example: "cargo test {{args}}" matches "cargo test", "cargo test
       --nocapture", "cargo test my_module::my_test", etc.

       Actions that fail to parse are non-matching (defense in depth:
       a malformed pattern never widens the allowlist, it only narrows).

       FOOTGUN: tokens like "--flag={{uuid}}" are rejected at 'byn trust'
       time as malformed patterns (a placeholder must occupy an entire
       whitespace-delimited token). To pass a flag with a variable value,
       either pin it literally ("--flag=abc123") or use a separate token
       pattern if the tool accepts it ("--flag {{uuid}}").

   AUTHORIZATION MODEL
       Actions pinlist ([exec] actions): controls WHICH commands may run
       without per-call authorization. Three states:

         empty or absent (DEFAULT — THE SECURE CHOICE)
             No command runs free. Every 'byn exec' requires
             authorization (the master password or a presence token).
             This is the secure default: a .byn with no [exec] actions
             declares it has not opted into any pinned commands.
             Migration note: existing .byn files that have been re-trusted
             after NU-2 will have empty actions — every exec will prompt
             until you pin commands.

         "*" or ["*"] (wildcard — LOUD WARNING)
             ALL commands run without re-authorization. The CLI prints a
             loud warning on every exec. Use only for fully-trusted
             automation environments.

         ["cmd arg1 arg2", ...] (explicit list with optional placeholders)
             Matching commands run free; all other commands require
             authorization. Use placeholders for variable arguments.
             "aws s3 ls" does NOT match "aws s3 ls --human" (no tail
             wildcard); use "aws s3 ls {{args}}" to match any trailing
             arguments. This is the recommended setting for production.

       [auth] exec policy (in the .byn [auth] table):
         "always"   fresh authorization required for EVERY exec, even
                    pinned/wildcard. Strongest: turns the .byn into a
                    scope-gating file only.
         "none"     no authorization for ANY command — wildcard-equivalent.
                    The loud warning is shown at 'byn trust' time (not at
                    exec time). Treat it as equivalent to actions = "*".
         "trusted"  default — let the actions list decide (see above).

       Actions enforcement is INDEPENDENT of the session gate.
       The session gate governs operations that have no .byn contract
       (ad-hoc exec, get, put, delete, …). A .byn's [exec] actions list
       is the contract for trusted-.byn exec.

       Ad-hoc exec (no .byn) is auth-gated when no session is present —
       the daemon returns auth_required, the CLI prompts once for the
       master password and retries. Trusted-.byn exec with an unmatched
       command is also gated (same retry flow; the daemon message explains
       that the command is not pinned). To avoid the prompt, pin the
       command in [exec] actions.

       Trust: when the scope comes from a discovered .byn, exec verifies
       it is trusted (machine + vault-key MAC, checked by the daemon)
       before injecting; an untrusted, changed, or tampered .byn aborts
       with a re-trust hint. Only exec gates on trust — other commands
       apply a .byn scope without a trust check. Approve with byn trust.

       Allowlist: a discovered .byn controls which vars exec injects via
       [exec] env — a name list injects only those, "*" (or ["*"]) injects
       all (with a warning, since later-added secrets auto-inject), and an
       empty or absent list injects nothing. With no .byn (ad-hoc run) the
       whole scope is injected.

       Values reach the child but never appear in the parent shell's
       environment, command-line, or shell history. They do appear in
       the child's environ (visible to anything with same-UID access
       to /proc/PID/environ, which is the inherent limit of env-var
       injection — for stronger isolation, future versions will use
       FUSE materialization).

       Values stored in the vault override any same-named variable in
       the parent shell (last-wins per POSIX). A DB_URL stored in
       byn takes precedence over one already exported in your shell.

       Requires an unlocked vault. Vault locked: exec always fails with
       "vault is locked". Unlike the delete family, exec cannot proceed
       with a password alone; run "byn unlock" first.

       Every exec attempt — allowed or denied, including locked-vault
       denials — is written to the vault's audit log with the full
       command line. Alias execs are logged as "alias NAME → resolved argv"
       (capped at 200 chars).

   PRIVILEGE SEPARATION
       With [security] privsep enabled in ~/.byn/config, a trusted-.byn
       pinned exec runs its child as the _byn-exec service user (set up
       via 'byn setup'), so other same-UID processes can't read the
       injected secrets from the child's environment. --no-privsep
       forces the in-process path. Ad-hoc exec (no .byn) always runs
       in-process.

       Privsep is opt-in and off by default. If [security] privsep is on
       but 'byn setup' has not provisioned the service users, exec fails
       with an actionable error rather than silently running in-process.

OPTIONS
       --no-privsep
           Force the legacy in-process exec path even when [security]
           privsep is enabled. The child is run by the calling user via
           execve(2) instead of the daemon spawning it under _byn-exec.
           Place it before the "--" separator (direct form) or before the
           alias NAME (alias form); tokens after that boundary are the
           child's argv.

EXAMPLES
       Direct form — run a python script with stored env vars set:
           $ byn exec -- python deploy.py

       Direct form — inspect what byn injects:
           $ byn exec -- env | grep -v '^_'

       Direct form — with flag-having commands; "--" makes them unambiguous:
           $ byn exec -- terraform apply -auto-approve

       Alias form — run the "deploy" alias defined in the .byn:
           $ byn exec deploy

       Alias form — pass extra args after the alias name:
           $ byn exec test -- --nocapture

       Alias form — shadow: run the binary named "test", not the alias:
           $ byn exec -- test

       Wrap a shell builtin via bash:
           $ byn exec -- bash -c 'cd $PROJECT_DIR && make build'

EXIT STATUS
       The exit code is the exit code of the child command (because
       execve replaces the process — there is no byn to translate).

       Exit codes BEFORE successful exec:
       0    (never; execve doesn't return on success)
       1    Bad usage, missing binary, or alias form without a .byn.
       2    Daemon unreachable.
       3    Daemon error: vault locked (always a hard failure for exec),
            untrusted/changed/tampered .byn (re-trust with byn trust),
            alias not found in [aliases].

SECURITY NOTES
       Once a value is in the child's environment, it is visible to
       any process with the same UID that can read /proc/PID/environ.
       This is a fundamental limit of env-var injection; byn exec
       defends against the parent shell's exposure surface (history,
       argv, ps) but not against same-UID process-memory inspection.

       For values that must not be visible even via /proc, future
       versions will use FUSE-projected files that are materialized
       only at the moment of read.

SEE ALSO
       byn(1), byn-get(1), byn-put(1), byn-trust(1)
`,

	"rename": `NAME
       byn-rename - rename a secret

SYNOPSIS
       byn rename [--password-stdin] OLD NEW
       byn mv OLD NEW

DESCRIPTION
       Renames the secret named OLD to NEW. Because the AEAD AAD is
       bound to the secret name, rename re-encrypts the value under
       the new name in the same database transaction. Requires unlock.

       Refuses if NEW is already taken.

       Rename requires the master password when no session is present.
       The CLI prompts interactively; scripts should use --password-stdin.

OPTIONS
       --password-stdin
           When no session is present, read the master password from stdin
           instead of prompting at the terminal.

EXAMPLES
       Rename a credential after rotation:
           $ byn rename aws-access-key-old aws-access-key

       Using the alias:
           $ byn mv foo bar

       Non-interactive rename (sessionless, via stdin):
           $ echo "$MASTER_PW" | byn rename old-name new-name --password-stdin

EXIT STATUS
       0    Renamed.
       1    Wrong number of arguments.
       2    Daemon unreachable.
       3    Daemon error: not found, name taken, vault locked.

SEE ALSO
       byn(1), byn-put(1)
`,

	"edit": `NAME
       byn-edit - open the modal TUI editor

SYNOPSIS
       byn edit [NAME]
       byn view [NAME]
       byn

DESCRIPTION
       Opens an alt-screen TUI for browsing and editing secrets. Uses
       vi-style modes (NORMAL / INSERT / COMMAND) and ex commands. The
       terminal's previous contents are restored when you quit, so
       revealed values never enter scrollback.

       If NAME is given, the cursor lands on that row pre-revealed.
       Running plain "byn" with no subcommand also opens the
       editor (initializes or unlocks the vault first if needed).

KEYS - normal mode
       j/k or arrow keys       move cursor
       gg / G                   top / bottom
       l / Enter / Right        reveal selected value (5s auto-hide)
       h / Esc                  mask a revealed value
       i, a                     edit selected value (drafts only)
       o                        new entry: type name, Enter, type value
       r                        rename selected
       dd                       delete selected (drafts only)
       :w                       commit drafts to the daemon
       :q                       quit (refuses with unsaved drafts)
       :q!                      discard drafts and quit
       :wq, :x                  commit and quit
       q                        same as :q
       Ctrl-C                   always exit (drafts lost)

KEYS - insert mode
       printable characters, backspace, arrow keys, Home, End
       Enter                    confirm (saves into the local draft)
       Esc                      cancel; on a blank new row, drops it

DRAFTS AND DIRTY STATE
       Edits are local drafts until you run :w. The header shows
       "N unsaved" while drafts exist. The left-column indicator on
       each row reflects state:
           (blank)   clean
           *         value or rename pending
           +         new entry, not yet committed
           -         marked for delete
           !         name collides with another entry

EXAMPLES
       Open and browse:
           $ byn edit

       Open with a row preselected:
           $ byn edit aws-access-key

REQUIREMENTS
       Stdin/stdout must be a real terminal. Piping or redirecting
       either is rejected with an explanation.

EXIT STATUS
       0    Clean quit.
       1    Not a terminal, or bad input.
       2    Daemon unreachable.
       3    Daemon error.

SEE ALSO
       byn(1), byn-put(1), byn-get(1)
`,

	"daemon": `NAME
       byn-daemon - control the background daemon

SYNOPSIS
       byn start [--foreground] [--allow-root]  (alias: byn daemon start)
       byn stop                      (alias: byn daemon stop)
       byn restart [--foreground] [--allow-root] (alias: byn daemon restart)
       byn reload                    (alias: byn daemon reload)
       byn status                    (alias: byn daemon status)
       byn daemon install
       byn daemon uninstall

DESCRIPTION
       Manages the per-user background daemon. The daemon owns the
       Unix socket, the in-memory vault key, and the SQLite database.
       It enforces same-UID access at the socket via the OS peer-
       credential check.

       The pidfile and socket live in the data directory (a fixed
       per-OS system path). Stale pidfiles (PID no longer alive) are
       detected and replaced on start.

       When privsep is provisioned (sudo byn setup), the daemon is the
       _byn launchd/systemd service: "byn start" (run as you) reports
       its status and points you to "sudo byn restart" if it is down —
       it never spawns a daemon as you; "sudo byn restart"/"stop" act on
       the service (a SIGTERM is futile — KeepAlive respawns it); "sudo
       byn reload" SIGHUPs it to re-read config.

SUBCOMMANDS
       start [--foreground] [--allow-root]
           Start the daemon. Detaches by default; --foreground keeps
           it in the foreground for supervised setups or development.
           The daemon REFUSES to run as root (uid 0): a root daemon
           defeats the _byn privilege separation it installs (least
           privilege). --allow-root overrides this (NOT recommended —
           posture hygiene only, not a defense against an existing
           root attacker) and logs a prominent warning.

       stop
           SIGTERM the daemon via the pidfile. Waits up to 5s for
           a graceful exit before warning.

       restart [--foreground] [--allow-root]
           Stop the running daemon (if any) and start a fresh one —
           one command instead of stop + start. Picks up a NEW
           binary and config. Degrades to a plain start when nothing
           is running. Forwards --foreground / --allow-root to start.

       reload
           Signal the running daemon (SIGHUP) to re-read ~/.byn/config
           and apply the runtime-changeable settings — idle_timeout,
           the web portal (enable/disable/port) — WITHOUT a restart.
           Open vaults stay unlocked. Use this for config tweaks; use
           restart to pick up a new binary. Applied changes are logged
           to the daemon log.

           Runtime-changeable config keys:
             [daemon]   idle_timeout   — vault auto-relock window
             [ui]       port, enabled, reveal_hide_after
             [security] session_ttl    — absolute session lifetime
                                         (default 12h; 0 = no limit)
             [security] session_idle   — sliding idle window
                                         (default 0 = inherit idle_timeout)
             [security] session_ttl / session_idle — tune session lifetime

       status
           Print daemon state, socket path, vault lock state, and
           uptime. "byn status" is an alias.

       install
           Register the daemon as a user auto-start service (launchd
           LaunchAgent on macOS, systemd --user unit on Linux) so it
           comes up on login. Writes the service file and loads it
           best-effort. No root required. This is the auto-start path
           for the default (non-privsep) install; privilege-separated
           installs use "byn setup" instead (which installs a SYSTEM
           service running the daemon as the _byn service user).

       uninstall
           Disable and remove the auto-start service.

EXAMPLES
       Start in detached mode:
           $ byn start

       Start in foreground (development, supervised launch):
           $ byn start --foreground

       Check status:
           $ byn status
           daemon:  running (version dev)
           socket:  /Users/you/.byn/daemon.sock
           vault:   unlocked
           uptime:  3h25m

       Stop:
           $ byn stop

       Apply config edits live (e.g. after changing idle_timeout):
           $ byn reload

EXIT STATUS
       0    Subcommand succeeded.
       1    Bad input, daemon not running (reload), or stop did not
            complete within 5s.
       2    daemon status: daemon was not running.

SEE ALSO
       byn(1), byn-status(1)
`,

	"status": `NAME
       byn-status - print daemon and vault state

SYNOPSIS
       byn status

DESCRIPTION
       Alias for "byn daemon status". Prints version, socket path,
       vault lock state (uninitialized / locked / unlocked), and
       daemon uptime.

       Vault state has two independent layers. "unlocked" means the
       daemon holds the vault key in memory (required for trusted exec
       / shim injection). Reading values also requires a per-terminal
       session: a terminal that never ran "byn unlock" will see
       "unlocked" but still be prompted to authorize on "byn get".
       Each vault row shows "[session: active, expires in …]" when the
       current terminal has a live session, or a dim "[no session in
       this terminal — byn unlock to authorize reads]" when it does not.

EXAMPLES
       Check state:
           $ byn status
           daemon:  running (version dev)
           socket:  /Users/you/.byn/daemon.sock
           vault:   unlocked
           uptime:  1h2m

EXIT STATUS
       0    Daemon responded.
       2    Daemon unreachable.

SEE ALSO
       byn(1), byn-daemon(1)
`,

	"web": `NAME
       byn-web - open the local browser admin portal

SYNOPSIS
       byn web
       byn ui

DESCRIPTION
       Opens the browser admin portal hosted by the daemon at
       http://localhost:2967 (configurable via [ui] port in
       ~/.byn/config). The portal is a web UI over the same vault the
       CLI and TUI use: browse the vault/project/env scope tree,
       create/delete scopes and vaults, view and edit env-var entries,
       and reveal values (each reveal is audited).

       There is no portal login. Like "byn ls", the scope tree and
       entry names are visible, but reading or editing VALUES requires
       the target vault to be unlocked -- a per-vault lock/unlock toggle
       in the UI. Write/delete/reveal actions trigger an in-page
       "Authorize" step-up: passkey (Touch ID) first, then password
       fallback. On success, the daemon issues a single-use presence
       token consumed by the retry. The portal binds loopback only
       (127.0.0.1), never the network; its CSRF defense is an Origin check.

       The portal includes a .byn STUDIO (top-left ".byn" button): a
       structured builder form, inline TOML validator, command tester
       (simulates the exec gate before trust is granted), and one-click
       save+trust. Open an existing trusted file via "open .byn..." or
       browse to any directory containing a .byn file. The Settings
       panel (top-right gear icon) exposes the global config file as a
       TOML editor -- editing config always requires the master password
       or a passkey token.

       Disable the portal entirely with [ui] enabled = false in
       ~/.byn/config (then restart the daemon).

EXAMPLES
       Open the portal:
           $ byn web
           byn web portal: http://localhost:2967

EXIT STATUS
       0    Browser launched (or URL printed).
       1    Portal disabled in config.
       2    Daemon unreachable.

SEE ALSO
       byn(1), byn-daemon(1), byn-trust(1)
`,

	"version": `NAME
       byn-version - print the binary version

SYNOPSIS
       byn version

DESCRIPTION
       Prints the version, build metadata (commit + date) baked in at
       build time, and the author/homepage. Same output for
       "byn --version" and "byn -v".

       byn is by Sandeep Baynes (https://github.com/sandeepbaynes/byn) and is licensed
       under the Business Source License 1.1 (source-available;
       converts to Apache-2.0 four years after each release).

EXAMPLES
           $ byn version
           byn 0.0.1
             a1b2c3d, built 2026-06-03
             by Sandeep Baynes · https://github.com/sandeepbaynes/byn

EXIT STATUS
       0    Always.

SEE ALSO
       byn(1)
`,

	"help": `NAME
       byn-help - print command help

SYNOPSIS
       byn help [COMMAND]
       byn COMMAND help
       byn COMMAND --help
       byn COMMAND -h

DESCRIPTION
       With no COMMAND, prints the top-level usage listing. With a
       COMMAND, prints detailed help for that command (the same
       content as the corresponding section of byn(1)).

       Every command supports the "--help" / "-h" / "help" suffix,
       matching the AWS CLI convention.

EXAMPLES
       Top-level overview:
           $ byn help

       Detailed help for a command (these are all equivalent):
           $ byn help put
           $ byn put help
           $ byn put --help
           $ byn put -h

SEE ALSO
       byn(1)
`,

	"vault": `NAME
       byn-vault - manage vaults

SYNOPSIS
       byn vault list [--json]
       byn vault delete NAME [--password-stdin]
       byn vault rename OLD NEW [--password-stdin]
       byn vault init | unlock | lock

DESCRIPTION
       Vaults are top-level containers. The "default" vault is
       protected — it cannot be deleted or renamed. Use --vault NAME
       (or BYN_VAULT) to target a non-default vault for any command.

       vault delete NAME [--password-stdin]
           Securely remove a vault from disk. Refuses the "default"
           vault. When the vault is locked or no session is present,
           the master password is required (--password-stdin for scripts).

       vault rename OLD NEW [--password-stdin]
           Rename a vault and its audit trail. Refuses the "default"
           vault and an existing destination. The vault is left LOCKED
           afterwards. Requires the master password when locked or when
           no session is present (--password-stdin for scripts).

       vault init | unlock | lock
           Aliases for the top-level lifecycle commands.

SEE ALSO
       byn-init(1), byn-unlock(1)
`,

	"project": `NAME
       byn-project - manage projects within a vault

SYNOPSIS
       byn project list [--json]
       byn project create NAME
       byn project delete NAME [--password-stdin]
       byn project rename OLD NEW

DESCRIPTION
       Projects partition env-vars and files inside a vault. The
       "default" project cannot be deleted or renamed — it is the
       inheritance base and the implicit scope for every command.

       project delete NAME [--password-stdin]
           Cascade-delete: removes the project + every env + every
           entry + every entry_version. Refuses "default". When the
           vault is locked or no session is present, the master password
           is required (--password-stdin for scripts).

       project rename OLD NEW
           Rename a project. Refuses to rename "default" (renaming it
           would break implicit scope resolution for every command that
           defaults to "default").

SEE ALSO
       byn-env(1)
`,

	"env": `NAME
       byn-env - manage envs within a project

SYNOPSIS
       byn env list [--json]
       byn env create NAME
       byn env delete NAME [--password-stdin]
       byn env clear [ENV] --yes [--password-stdin]
       byn env rename OLD NEW

DESCRIPTION
       Envs are the leaf scope (e.g. dev, staging, prod). The
       project's "default" env cannot be deleted or renamed. Non-default
       envs fall back to default for missing keys (inheritance).

       env delete NAME [--password-stdin]
           Delete a non-default env and cascade to its entries.
           Refuses "default". When the vault is locked or no session is
           present, the master password is required (--password-stdin
           for scripts).

       env clear [ENV] --yes [--password-stdin]
           Delete every env-var in ENV (defaults to the active env)
           while keeping the env itself. --yes is required to proceed.
           Treated as a destructive operation: the master password is
           required when the vault is locked or no session is present.

       env rename OLD NEW
           Rename an env. Refuses "default".

SEE ALSO
       byn-project(1)
`,

	"import": `NAME
       byn-import - bulk-load env-vars from .env / .yaml / .json

SYNOPSIS
       byn import [--format env|yaml|json] [--dry-run]
                     [--skip-existing | --replace [--yes]] [PATH | -]

DESCRIPTION
       Reads a flat key→value file and creates env-var entries in the
       active scope. Format is inferred from extension first, then
       sniffed; pass --format to force.

       Nested objects are rejected. Use --dry-run to preview key
       names and value sizes without writing.

       Three modes (mutually exclusive):
         merge (default)   add new keys; overwrite matching ones;
                           leave other keys in the scope untouched.
         --skip-existing   add-only: refuse to overwrite existing keys.
         --replace         destructive: wipe every existing key in the
                           scope, THEN import. Requires confirmation in
                           an interactive terminal; pass --yes to skip
                           the prompt (required in non-TTY/agent mode).

OPTIONS
       --format env|yaml|json
           Force input format.

       --dry-run
           Print what would be imported (including deletions when
           combined with --replace); nothing is written.

       --skip-existing
           Add-only mode. Existing keys count as "skipped".

       --replace
           Wipe scope first, then import. Operation order: list +
           delete each entry in scope.Project/scope.Env, then run the
           normal import loop.

       --yes
           Skip the --replace confirmation prompt. Required when
           stdin is not a TTY (scripts, CI, agents).

EXAMPLES
       Pipe a dotenv file (merge — today's default):
           $ cat .env.local | byn --project myapp import

       Dry-run preview from YAML:
           $ byn import --dry-run config.yaml

       Add-only (refuse overwrites):
           $ byn import --skip-existing config.env

       Replace every entry in scope with the file's contents:
           $ byn import --replace --yes config.env

       Preview a replace operation (lists both deletions and adds):
           $ byn import --replace --dry-run config.env

SEE ALSO
       byn-export(1)
`,

	"export": `NAME
       byn-export - dump env-vars to .env / .yaml / .json

SYNOPSIS
       byn export [--format env|yaml|json] [--output PATH]
                  [--password-stdin]

DESCRIPTION
       Materializes all env-var entries in the active scope as a
       single flat key→value document. Writes to stdout by default,
       or to PATH with --output (mode 0600).

       With an active terminal session (from a prior "byn unlock")
       every get is authorized by the session token — no password
       prompts fire. Without a session, the first get returns
       auth_required; the CLI prompts once interactively (or reads
       from --password-stdin) and reuses the same password for the
       remaining entries. Each per-password get re-verifies via
       Argon2id, so large exports without a session are slow; run
       "byn unlock" first (or use --password-stdin) to avoid this.

OPTIONS
       --format env|yaml|json
           Output format (default: env).

       --output PATH | -
           Destination file, or "-" for stdout.

       --password-stdin
           The non-interactive way to supply the master password when
           no session is present — reads it from stdin instead of
           prompting at the terminal. Useful for scripts and CI.

CAVEATS
       This command MATERIALIZES PLAINTEXT. Treat the destination as
       you would a .env file: never commit, never share.

SEE ALSO
       byn-import(1)
`,

	"doctor": `NAME
       byn-doctor - diagnose (and optionally repair) byn's health

SYNOPSIS
       byn doctor [--json]
       sudo byn doctor --repair

DESCRIPTION
       Runs two batteries. The LOCAL provisioning/health checks work even
       when the daemon is DOWN (exactly when you need them):
         • privsep provisioned     — the _byn service users exist
         • spawn helper installed  — the setuid helper is in place
         • daemon running          — the socket is reachable
         • data dir owned by _byn  — flags root-owned strays a "sudo byn
                                     start" left behind
         • no stale socket         — a leftover socket with the daemon down

       When the daemon IS reachable it also runs the daemon-side checks:
         • vaults.list     — vaults present on disk
         • vault[X].open   — schema version + meta.json fingerprint
         • vault[X].audit  — HMAC chain verifies end-to-end

       Exit code is non-zero if any check fails. Plain "byn doctor" only
       diagnoses (dry-run).

OPTIONS
       --repair
           Apply the safe fixes for the failing LOCAL checks: chown the data
           dir back to _byn, reload the launchd/systemd service (clearing a
           stale socket and a broken registration). Requires root — run as
           "sudo byn doctor --repair". This is the packaged form of the manual
           launchctl bootout/bootstrap + chown recovery.

       --json
           Emit the structured result instead of human output.

SEE ALSO
       byn-audit(1), byn-status(1), byn-setup(1)
`,

	"audit": `NAME
       byn-audit - read and verify the per-vault audit log

SYNOPSIS
       byn audit view [--lines N] [--json]
       byn audit tail [-n N] [-f] [--json]
       byn audit verify [--json]
       byn audit reseal [--reason R] [--yes] [--json]

DESCRIPTION
       Each vault has an append-only HMAC-chained audit log under
       <data-dir>/audit/<vault>/YYYY-MM.log. All subcommands work
       while the vault is locked (the log is metadata, not values).

       Human rows are: timestamp + op + scope + entry + outcome +
       caller. The caller column identifies who ran it: surface
       (socket = CLI/TUI, portal = browser), process name, pid/uid,
       and the parent process — e.g. "socket:byn(pid 9123, uid 501)
       ←node". --json exposes caller_uid / caller_pid / caller_comm /
       caller_pcomm / caller_surface.

       byn audit view
           Snapshot the last N events and exit (default 50;
           --lines 0 returns all).

       byn audit tail
           Like tail(1): print the last N events (default 10, -n N),
           and exit. With -f, follow — keep streaming new events in
           realtime until Ctrl-C (NDJSON with --json -f).

       byn audit verify
           Re-walk the chain end-to-end and recompute every
           hmac_chain. Exits 0 with "intact" on success; exits 3
           with "BROKEN at event #M" + a treat-as-compromised hint
           if any link fails.

       byn audit reseal
           Acknowledge a chain break (e.g. one a daemon crash left
           mid-write) by appending a SIGNED bridge marker — the
           original hashes are never rewritten, so the gap stays
           visible and attributable (records the break, the reason,
           and who/when). Afterwards verify and doctor read the chain
           as intact. The vault must be UNLOCKED. Prompts for a reason
           and confirmation; --reason with --yes runs non-interactively.
           A marker forged without the chain seed cannot clear a break.

EXAMPLES
       Recent 20 events for the active vault:
           $ byn audit tail --lines 20

       Confirm the log hasn't been tampered with:
           $ byn audit verify

       Pipe to an agent for analysis:
           $ byn audit tail --json | jq '.[] | select(.outcome != "ok")'

SEE ALSO
       byn-doctor(1)
`,

	"trust": `NAME
       byn-trust - approve a .byn discovery file (TOFU)

SYNOPSIS
       byn trust [PATH...] [--paths "a,b,c"] [--recursive] [--password-stdin]
       byn trust diff <PATH>
       byn trust list [--json]
       byn untrust [PATH...] [--paths "a,b,c"] [--recursive]

DESCRIPTION
       byn discovers a .byn TOML file by walking up from CWD; its
       [scope] table pins an active vault/project/env. A .byn must be
       trusted before its scope is applied.

       Granting trust ALWAYS requires the master password — even when
       the vault is unlocked — because approving a .byn is a
       proof-of-presence action. The daemon owns the trust store and
       verifies the password (against the vault the .byn targets)
       before recording the canonical path + SHA-256 of the contents.

       Trusting many files at once groups them by their target vault and
       asks each vault's password ONCE — so a monorepo's per-project .byn
       files cost one prompt per vault, not one per file. Untrust takes
       the same path forms but needs no password (revoking is fail-safe).

       Discovery itself is read-only and NEVER auto-trusts: a new or a
       CHANGED .byn (its hash no longer matches) is refused — in both
       interactive and agent mode — until you re-approve it with
       'byn trust'. This closes the silent-re-trust path: a modified
       file is never honored on a y/N, and an agent driving the CLI
       can't approve a file whose password it doesn't have.

       .byn files exceeding 64KB are refused at grant time and at exec.

[auth] TABLE — per-scope per-action authorization policy
       A .byn may carry an [auth] table that overrides the global session
       gate for operations in this file's scope. Keys: get, update
       (overwrite-put, rename), delete (delete, env.clear, env.delete,
       project.delete, vault.delete), exec. Values:

         "always"  Fresh authorization required for every matching op,
                   even when a session is active. Tightens.

         "none"    Gate skipped entirely for the matched scope, even when
                   no session is present. Relaxes. Use only in environments
                   where ambient access is acceptable (e.g., a local dev
                   project with no sensitive creds).

         absent    The session gate decides (default).

       Policy is MAC-bound at grant time: the daemon reads the policy
       from the trust record (not the live file) so editing the .byn
       after trust cannot change the effective policy without re-trusting
       (which requires the password). See byn-security(7) for lookup
       rules: specificity, strictest-tie, and locked-vault fall-through.

       Structural-ops note: vault-level ops (vault.delete, vault.rename)
       pass Scope{} (no project/env) to the policy gate. A vault-only
       record (no project/env in [scope]) matches and therefore gates
       those ops — a record scoped broadly to an entire vault is deliberate.

       Cross-reference: the [auth] exec key and [exec] actions are
       independent. The exec key applies ONLY to trusted-.byn exec; ad-hoc
       exec (no .byn) is auth-gated when no session is present.
       See 'byn help exec' for the full exec authorization matrix.

OPTIONS
       PATH...
           One or more .byn files. A directory resolves to <dir>/.byn.
           Default: ./.byn.

       --paths "a,b,c"
           Comma-separated list of .byn files or directories to (un)trust.

       --recursive
           Walk each given directory for every .byn under it.

       --password-stdin (trust only)
           Read the master password from stdin instead of prompting
           (for scripts/CI). With multiple vaults, run interactively.

       --json (trust list only)
           Print the trust store as a JSON array.

EXAMPLES
       Approve the file in the current project (prompts for password):
           $ byn trust

       Approve non-interactively:
           $ printf '%s' "$PW" | byn trust --password-stdin ./.byn

       See what changed since the last approval:
           $ byn trust diff ./.byn

       Changed → diff → re-trust flow:
           $ byn exec -- make build   # fails: .byn has CHANGED
           $ byn trust diff ./.byn    # review unified diff
           $ byn trust ./.byn         # re-approve (prompts for password)
           $ byn exec -- make build   # succeeds

       List trusted paths:
           $ byn trust list

       Revoke trust:
           $ byn untrust ./.byn

TROUBLESHOOTING
       macOS, "operation not permitted" (distinct from "permission
       denied"): the daemon runs as _byn and macOS privacy protection
       (TCC) blocks it from reading .byn files under ~/Documents,
       ~/Desktop, ~/Downloads or iCloud Drive. TCC overrides file ACLs,
       so chmod/setfacl cannot fix it. Two resolutions:

       Option A (recommended): keep byn projects outside those folders
       (e.g. ~/code) — no Full Disk Access or code signing needed.

       Option B: grant the byn binary Full Disk Access in System Settings
       > Privacy & Security > Full Disk Access, then restart the daemon:
           sudo launchctl kickstart -k system/com.sandeepbaynes.byn
       The grant is tied to the build unless you sign with a (free) Apple
       ID identity so it persists across reinstalls:
           make install CODESIGN_IDENTITY="Apple Development: you (TEAMID)"

       Full steps incl. code-signing and the paid Developer ID path for
       distributing to other Macs: man byn ("macOS Full Disk Access") or
       docs/troubleshooting.md.

EXIT STATUS
       byn trust diff exits 0 when the file is identical (content and
       modification time unchanged). It exits 1 when the content
       differs or the modification time changed without a content change
       (re-trust required either way). It exits 2 when the daemon is
       not running and 3 when the daemon returns an error (e.g. path
       not trusted, file exceeds 64KB).

SEE ALSO
       byn(1) — discovery walk + .byn file format
`,

	"untrust": `NAME
       byn-untrust - revoke trust for a .byn file

SYNOPSIS
       byn untrust [PATH]

DESCRIPTION
       Remove the trust record for PATH (default: ./.byn) from
       <data-dir>/trusted_byn.json. Idempotent — succeeds
       silently if the path was not trusted.

SEE ALSO
       byn-trust(1)
`,

	"setup": `NAME
       byn-setup - provision (or remove) privilege separation for the daemon

SYNOPSIS
       sudo byn setup
       sudo byn setup --uninstall [--purge]

DESCRIPTION
       Provisions the full privilege-separation install in one idempotent,
       root-required step. byn setup:

         1. Creates the _byn and _byn-exec service accounts and installs the
            prebuilt privileged spawn helper (byn-exec-helper) plus its
            root-owned UID/GID config.
         2. Installs and loads the system service that runs the daemon as the
            _byn service user (a systemd system unit on Linux, a LaunchDaemon
            on macOS) — NOT the human owner.
         3. Relocates any legacy per-user ~/.byn vault into the fixed per-OS
            system data path, chowned to _byn (trust + passkeys preserved —
            same machine). Skipped on a fresh install with no legacy vault.
         4. Records the OWNER UID — the human who ran sudo — as the single UID
            the daemon allowlists on its peer-credential-gated socket. byn
            setup reads SUDO_UID for this; running as real root (not via sudo)
            fails rather than recording root as the owner.
         5. Verifies the post-conditions (system data dir present + owned by
            _byn, owner record readable).

       This command MUST be run as root, via sudo so SUDO_UID is set. It is
       idempotent: re-running on an already-provisioned host (re)installs the
       helper + service, re-records the owner, and exits 0 — safe on every
       install and upgrade. The prebuilt byn-exec-helper must sit beside the
       byn binary; if it is missing, setup fails telling you to reinstall byn.
       On platforms other than Linux and macOS, byn setup is not supported.

       Setup provisions privsep; it does not enable it. Privilege separation is
       opt-in: set "[security] privsep = true" in ~/.byn/config and restart the
       daemon to engage it. With privsep enabled and provisioned, the daemon
       spawns trusted-.byn pinned exec children as _byn-exec. Enable privsep
       WITHOUT having run setup and the daemon warns and trusted-.byn exec fails
       closed (it never silently runs owner-UID).

       --uninstall reverses a previous setup: it uninstalls the system service,
       removes the spawn helper + its config, and removes the owner record. By
       default it LEAVES the vault (the system data dir) intact. Add --purge to
       ALSO delete the system data dir and every secret in it — a destructive
       action gated behind a typed "yes" confirmation. The vault is NEVER
       removed without --purge.

OPTIONS
       --uninstall
           Reverse a previous setup. Removes the service, spawn helper, and
           owner record; keeps the vault unless --purge is also given.

       --purge
           With --uninstall, ALSO remove the system data dir (the vault and all
           secrets). Destructive and irreversible; requires a typed confirmation.

EXAMPLES
       Provision privsep on a fresh install:
           $ sudo byn setup
           byn provisioned: daemon runs as _byn, owner UID 501 allowlisted

       Re-run after upgrading byn (idempotent):
           $ sudo byn setup

       Uninstall privsep but keep the vault:
           $ sudo byn setup --uninstall

       Uninstall AND destroy the vault:
           $ sudo byn setup --uninstall --purge

EXIT STATUS
       0    Provisioning / teardown succeeded (or was already complete).
       1    Not run as root, no SUDO_UID (run via sudo), missing prebuilt
            helper, a relocate/verify failure, or an aborted purge.

SEE ALSO
       byn(1), byn-daemon(1), byn-migrate(1)
`,

	"migrate": `NAME
       byn-migrate - adopt a byn vault into the system data path

SYNOPSIS
       sudo byn migrate
       sudo byn migrate --from <path> [--force]

DESCRIPTION
       Adopts a byn vault tree into the daemon's fixed per-OS system data
       path, with the correct structure and ownership (the _byn service
       account, mode 0700). Before adopting, the vault is verified WITHOUT
       its password — every vault.db opens as a well-formed, correctly-
       versioned SQLite vault whose wrapped.key/meta.json fingerprint
       matches and whose audit chain is intact. A malformed, truncated, or
       tampered source is rejected and the destination is left untouched.
       The adopt is atomic (stage + verify + rename); it never half-migrates
       and is safe to re-run.

       This command MUST be run as root (it writes the _byn-owned system
       path and chowns the adopted tree). The _byn service account must
       already exist; if it does not, run "byn setup" first. byn migrate
       adopts with the correct ownership — it does not create users.

   RELOCATE (no --from)
       Moves the legacy per-user ~/.byn into the system path — the upgrade
       path for an install that predates the system data root. Because it is
       the SAME machine, the trust store and passkey enrollments are KEPT.
       The old ~/.byn is removed only AFTER the destination is fully adopted
       (fail-safe: an interrupted relocate never leaves you with no vault).

   IMPORT (--from <path>)
       Copies an EXTERNAL vault (a backup, a mounted disk, a synced dir)
       into the system path. The source is NEVER deleted. A non-empty
       destination is refused unless --force is given.

       An import brings vault DATA only. The trust store and passkey
       enrollments are DROPPED — trust is never silently carried across a
       source/machine boundary (.byn trust fingerprints bind the machine
       and path, so a carried record would fail verification anyway). After
       an import you MUST re-trust your .byn files (byn trust) and re-enroll
       passkeys on this machine. The verification above runs on the original
       artifacts BEFORE the drop, so a hostile import is rejected before
       anything is dropped or committed.

OPTIONS
       --from <path>
           Import an external vault rooted at <path> instead of relocating
           the legacy ~/.byn. The source directory is left untouched.

       --force
           Replace a non-empty destination. Without it, a non-empty system
           data path is refused so a migrate never clobbers an existing
           vault. The old tree is moved aside and removed only after the new
           one is in place.

EXAMPLES
       Upgrade a legacy ~/.byn install to the system path:
           $ sudo byn migrate

       Import a vault from a backup directory:
           $ sudo byn migrate --from /mnt/backup/.byn
           imported /mnt/backup/.byn -> ... (source left untouched)

           Adopted DATA only. Trust grants and passkey enrollments are NOT
           carried across an import.
           Re-trust your .byn files (byn trust) and re-enroll passkeys.

       Replace an existing system vault with an import:
           $ sudo byn migrate --from /mnt/backup/.byn --force

EXIT STATUS
       0    Migration succeeded.
       1    Not root, _byn not provisioned (run byn setup), verification
            failed (malformed/tampered source), or a non-empty destination
            without --force.

SEE ALSO
       byn(1), byn-setup(1), byn-trust(1)
`,
}
