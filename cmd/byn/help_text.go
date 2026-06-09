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

       The vault is created at:
           $BYN_DIR/vaults/default/
       where $BYN_DIR defaults to ~/.byn. Files written:
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

       Each vault lives under $BYN_DIR/vaults/<name>/ with its own
       wrapped key, SQLite DB, audit log, and meta.json.

CHOOSING THE DATA DIRECTORY
       The data root is overridden via the BYN_DIR environment
       variable; a --data-dir flag is planned for a future release.
       Both the daemon and the CLI must see the same BYN_DIR.

           $ export BYN_DIR=/path/to/data
           $ byn start
           $ byn init

EXAMPLES
       Interactive (prompts twice for confirmation):
           $ byn init

       Scripted:
           $ echo "$MASTER_PW" | byn init --password-stdin

       In a fresh dev sandbox:
           $ export BYN_DIR=/tmp/byn-demo
           $ byn start
           $ byn init

       Separate vault per org via BYN_DIR (today's multi-vault):
           $ BYN_DIR=~/.byn-acme byn start
           $ BYN_DIR=~/.byn-acme byn init

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
       byn-unlock - unlock the vault for this daemon session

SYNOPSIS
       byn unlock [--password-stdin]

DESCRIPTION
       Prompts for the master password and asks the daemon to derive
       the vault key. On success, future put/get/rename calls succeed
       until "byn lock" or the daemon is stopped.

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
       byn lock

DESCRIPTION
       Asks the daemon to zero the in-memory vault key. Subsequent
       value reads/writes will return a "vault is locked" error until
       the vault is unlocked again.

       Locking does NOT stop the daemon. The metadata index remains
       browseable; only value reads require unlock.

EXAMPLES
           $ byn lock

EXIT STATUS
       0    Vault locked (or was already locked).
       2    Daemon unreachable.

SEE ALSO
       byn(1), byn-unlock(1)
`,

	"put": `NAME
       byn-put - store a secret

SYNOPSIS
       byn put [--create-only] NAME

DESCRIPTION
       Stores or updates a secret called NAME. The secret value is
       read from stdin — never the command line — so it does not show
       up in argv, ps output, shell history, or audit logs.

       Existing secrets are upserted by default. Use --create-only to
       refuse overwrites.

       Requires an unlocked vault.

OPTIONS
       --create-only
           Fail with "already exists" instead of overwriting an
           existing secret with the same name.

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
       byn get NAME
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
       byn delete NAME
       byn rm NAME

DESCRIPTION
       Removes the named secret. Does NOT require unlock — the
       metadata-only operation can be performed while the vault is
       locked.

       Without versioning enabled, deletion is immediate and
       unrecoverable.

EXAMPLES
       Delete an entry:
           $ byn delete tls-key

       Delete using the alias:
           $ byn rm old-token

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
       byn exec -- COMMAND [ARGS...]

DESCRIPTION
       Loads all env-var entries from the active vault scope, sets
       them in a child process's environment, and replaces the
       current byn process with the child via execve(2). The child
       runs as the same PID as the byn CLI that invoked it; there
       is no byn process left in the tree.

       The "--" separator is required to disambiguate exec's own
       flags from the child command's flags. Anything after "--" is
       the child argv.

       Values reach the child but never appear in the parent shell's
       environment, command-line, or shell history. They do appear in
       the child's environ (visible to anything with same-UID access
       to /proc/PID/environ, which is the inherent limit of env-var
       injection — for stronger isolation, future versions will use
       FUSE materialization).

       Values stored in the vault override any same-named variable in
       the parent shell (last-wins per POSIX). A DB_URL stored in
       byn takes precedence over one already exported in your
       shell.

       Requires an unlocked vault.

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
         - [exec] env is ENV-VARS ONLY — it does not restrict WHICH
           command runs; a trusted .byn runs any command you pass.
         - The .byn is strict TOML: any key outside [scope] / [exec] env
           is a hard parse error (no silent fallback).

       v1 limitations (iterating):
         - uses the implicit default scope (vault=default,
           project=default, env=default). --vault / --project / --env
           flags will land in a later iteration.
         - performs one IPC round-trip per stored entry (a "get all"
           daemon op will replace this when needed).
         - shell builtins (cd, source, ulimit, etc.) cannot be exec'd
           directly — wrap them in "bash -c '...'".

EXAMPLES
       Run a python script with stored env vars set:
           $ byn exec -- python deploy.py

       Inspect what byn sets:
           $ byn exec -- env | grep -v '^_'

       Run any binary; values flow into its environ:
           $ byn exec -- aws s3 ls

       Wrap a shell builtin via bash:
           $ byn exec -- bash -c 'cd $PROJECT_DIR && make build'

       Use with flag-having commands; the "--" makes them
       unambiguous:
           $ byn exec -- terraform apply -auto-approve

EXIT STATUS
       The exit code is the exit code of the child command (because
       execve replaces the process — there is no byn to translate).

       Exit codes BEFORE successful exec:
       0    (never; execve doesn't return on success)
       1    Bad usage, missing binary, vault locked, daemon issue.
       2    Daemon unreachable.
       3    Daemon error (vault locked, etc.).

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
       byn(1), byn-get(1), byn-put(1)
`,

	"rename": `NAME
       byn-rename - rename a secret

SYNOPSIS
       byn rename OLD NEW
       byn mv OLD NEW

DESCRIPTION
       Renames the secret named OLD to NEW. Because the AEAD AAD is
       bound to the secret name, rename re-encrypts the value under
       the new name in the same database transaction. Requires unlock.

       Refuses if NEW is already taken.

EXAMPLES
       Rename a credential after rotation:
           $ byn rename aws-access-key-old aws-access-key

       Using the alias:
           $ byn mv foo bar

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
       byn start [--foreground]      (alias: byn daemon start)
       byn stop                      (alias: byn daemon stop)
       byn restart [--foreground]    (alias: byn daemon restart)
       byn reload                    (alias: byn daemon reload)
       byn status                    (alias: byn daemon status)
       byn daemon install
       byn daemon uninstall

DESCRIPTION
       Manages the per-user background daemon. The daemon owns the
       Unix socket, the in-memory vault key, and the SQLite database.
       It enforces same-UID access at the socket via the OS peer-
       credential check.

       The pidfile and socket live in the data directory (see
       BYN_DIR). Stale pidfiles (PID no longer alive) are detected
       and replaced on start.

SUBCOMMANDS
       start [--foreground]
           Start the daemon. Detaches by default; --foreground keeps
           it in the foreground for supervised setups or development.

       stop
           SIGTERM the daemon via the pidfile. Waits up to 5s for
           a graceful exit before warning.

       restart [--foreground]
           Stop the running daemon (if any) and start a fresh one —
           one command instead of stop + start. Picks up a NEW
           binary and config. Degrades to a plain start when nothing
           is running.

       reload
           Signal the running daemon (SIGHUP) to re-read ~/.byn/config
           and apply the runtime-changeable settings — idle_timeout
           and the web portal (enable/disable/port) — WITHOUT a
           restart. Open vaults stay unlocked. Use this for config
           tweaks; use restart to pick up a new binary. Applied
           changes are logged to the daemon log.

       status
           Print daemon state, socket path, vault lock state, and
           uptime. "byn status" is an alias.

       install
           Register the daemon as a user auto-start service (launchd
           LaunchAgent on macOS, systemd --user unit on Linux) so it
           comes up on login. Writes the service file, loads it
           best-effort, and respects BYN_DIR. No root required.

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
       in the UI. The portal binds loopback only (127.0.0.1), never the
       network; its CSRF defense is an Origin check.

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
       byn(1), byn-daemon(1)
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
       byn vault delete NAME
       byn vault init | unlock | lock

DESCRIPTION
       Vaults are top-level containers. The "default" vault is
       protected — it cannot be deleted. Use --vault NAME (or
       BYN_VAULT) to target a non-default vault for any other
       command.

SEE ALSO
       byn-init(1), byn-unlock(1)
`,

	"project": `NAME
       byn-project - manage projects within a vault

SYNOPSIS
       byn project list [--json]
       byn project create NAME
       byn project delete NAME
       byn project rename OLD NEW

DESCRIPTION
       Projects partition env-vars and files inside a vault. Default
       project is "default" and cannot be deleted. Cascading delete
       removes all envs and entries under the project.

SEE ALSO
       byn-env(1)
`,

	"env": `NAME
       byn-env - manage envs within a project

SYNOPSIS
       byn env list [--json]
       byn env create NAME
       byn env delete NAME
       byn env rename OLD NEW

DESCRIPTION
       Envs are the leaf scope (e.g. dev, staging, prod). The
       project's default env cannot be deleted. Non-default envs fall
       back to default for missing keys (inheritance).

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

DESCRIPTION
       Materializes all env-var entries in the active scope as a
       single flat key→value document. Writes to stdout by default,
       or to PATH with --output (mode 0600).

OPTIONS
       --format env|yaml|json
           Output format (default: env).

       --output PATH | -
           Destination file, or "-" for stdout.

CAVEATS
       This command MATERIALIZES PLAINTEXT. Treat the destination as
       you would a .env file: never commit, never share.

SEE ALSO
       byn-import(1)
`,

	"doctor": `NAME
       byn-doctor - run self-checks on the daemon and every vault

SYNOPSIS
       byn doctor [--json]

DESCRIPTION
       Reports per-check ok / warn / fail across:
         • daemon          — running?
         • vaults.list     — vaults present on disk
         • vault[X].open   — schema version + meta.json fingerprint
         • vault[X].audit  — HMAC chain verifies end-to-end

       Exit code is non-zero if any check is "fail".

OPTIONS
       --json
           Emit the structured DoctorResp instead of human output.

SEE ALSO
       byn-audit(1), byn-status(1)
`,

	"audit": `NAME
       byn-audit - read and verify the per-vault audit log

SYNOPSIS
       byn audit view [--lines N] [--json]
       byn audit tail [-n N] [-f] [--json]
       byn audit verify [--json]

DESCRIPTION
       Each vault has an append-only HMAC-chained audit log under
       $BYN_DIR/audit/<vault>/YYYY-MM.log. All subcommands work
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

       List trusted paths:
           $ byn trust list

       Revoke trust:
           $ byn untrust ./.byn

SEE ALSO
       byn(1) — discovery walk + .byn file format
`,

	"untrust": `NAME
       byn-untrust - revoke trust for a .byn file

SYNOPSIS
       byn untrust [PATH]

DESCRIPTION
       Remove the trust record for PATH (default: ./.byn) from
       $BYN_DIR/trusted_byn.json. Idempotent — succeeds
       silently if the path was not trusted.

SEE ALSO
       byn-trust(1)
`,
}
