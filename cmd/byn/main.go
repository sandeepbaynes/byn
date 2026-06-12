// Command byn is the user-facing CLI.
//
// Architecture: cmd/byn is a thin IPC client. All business logic
// lives in the daemon (internal/daemon). The CLI's job is to parse
// flags, prompt for passwords, render results, and print actionable
// error messages with exit codes that scripts can branch on.
//
// Exit codes:
//
//	0  success
//	1  generic error (bad input, runtime failure, etc.)
//	2  daemon unreachable — print recovery hint
//	3  daemon returned a typed error (wrong password, not found, etc.)
package main

import (
	"fmt"
	"os"
	"strings"
)

// Build metadata. version/commit/buildDate are stamped at build time via
// -ldflags '-X main.version=... -X main.commit=... -X main.buildDate=...'.
// The defaults let a plain `go build` still report a sensible version.
var (
	version   = "0.0.1"
	commit    = ""
	buildDate = ""
)

const (
	appAuthor   = "Sandeep Baynes"
	appHomepage = "https://github.com/sandeepbaynes/byn"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	// Strip global scope flags (--vault/--project/--env) from anywhere
	// in argv before subcommand routing. This lets users write either
	//   byn --vault acme exec -- ...
	//   byn exec --vault acme -- ...
	// The pre-parser stops at a literal `--` so child arguments to
	// `exec` are not consumed.
	// Detect agent-mode (--json) and discovery opt-out BEFORE the
	// pre-parser so we can pass the right flags to discoverScope.
	agentMode := jsonModeFromArgs(args)
	noDiscovery := noDiscoveryFromArgs(args)
	if noDiscovery {
		args = stripFlagToken(args, "--no-discovery")
	}

	scope, scrubbed, err := preParseGlobals(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	args = scrubbed

	// `.byn` discovery + TOFU. Walk parents from CWD; fold the
	// result UNDER any explicit CLI flags or env vars. Errors here are
	// fatal (we don't want to silently apply the wrong scope).
	//
	// Skip for subcommands that manage trust itself or have no scope:
	// otherwise an untrusted .byn would prevent the user from ever
	// running `byn trust` to fix it.
	if !noDiscovery && len(args) > 0 && !skipDiscoveryFor(args[0]) {
		cwd, _ := os.Getwd()
		home, _ := os.UserHomeDir()
		bynDir, derr := defaultDir()
		if derr == nil {
			discScope, srcPath, derr := discoverScope(cwd, home, bynDir, agentMode)
			if derr != nil {
				fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), derr)
				return exitErr
			}
			if srcPath != "" {
				scope = mergeDiscoveryScope(scope, discScope)
				scope.SourcePath = srcPath // byn exec verifies trust against this
				hintf("Using scope from %s: %s.", srcPath, scope)
			}
		}
	}

	if len(args) == 0 {
		// No subcommand → open the TUI. Daemon-down, no-vault, and
		// locked states are handled inside runTUI with appropriate
		// recovery hints. Scope flags (and discovered .byn scope)
		// pre-position the rail cursor and pre-unlock the right vault.
		return runTUI(nil, scope)
	}
	cmd, rest := args[0], args[1:]

	// Top-level help/version handling — these never carry their own
	// "help" sub-argument.
	switch cmd {
	case "version", "--version", "-v":
		printVersion()
		return 0
	case "help", "--help", "-h":
		// "byn help <command>" routes to that command's help blob.
		if len(rest) > 0 {
			return printCommandHelp(rest[0])
		}
		printUsage(os.Stdout)
		return 0
	}

	// "byn <cmd> help" / "byn <cmd> --help" / "byn <cmd> -h"
	// — AWS-CLI convention. Intercept before subcommand routing so
	// the per-command help blob is shown instead of running the
	// command with a bogus arg.
	//
	// Exec passthrough exception: for `byn exec NAME ...`, a --help
	// after the alias name is meant for the alias's child process, not
	// byn.  wantsHelp is called with the exec-boundary-trimmed slice so
	// `byn exec myalias --help` does NOT show byn help.
	// `byn exec --help` (no alias name) still shows byn exec help.
	helpArgs := rest
	if cmd == "exec" {
		// Find the exec passthrough boundary within rest.
		// rest = args after "exec", so boundary relative to original
		// argv is already past the "exec" token.
		for bi, a := range rest {
			if a == "--" {
				// Direct form: trim at "--".
				helpArgs = rest[:bi]
				break
			}
			if !strings.HasPrefix(a, "-") {
				// This is the alias name. Everything from here is opaque —
				// help check must not see it.
				// Exception: "help" as the alias name is byn's own meta-command,
				// not a real alias (e.g. `byn exec help` shows exec help).
				if a == "help" {
					// Leave helpArgs = rest so wantsHelp sees "help" and fires.
					break
				}
				helpArgs = rest[:bi]
				break
			}
		}
	}
	if wantsHelp(helpArgs) {
		return printCommandHelp(cmd)
	}

	switch cmd {
	case "init":
		return runInit(rest, scope)
	case "daemon":
		return runDaemon(rest)
	case "start":
		return runDaemonStart(rest)
	case "stop":
		return runDaemonStop(rest)
	case "restart":
		return runDaemonRestart(rest)
	case "reload":
		return runDaemonReload(rest)
	case "status":
		return runStatus(rest)
	case "unlock":
		return runUnlock(rest, scope)
	case "lock":
		return runLock(rest, scope)
	case "passwd", "password":
		return runPasswd(rest, scope)
	case "put":
		return runPut(rest, scope)
	case "get", "cat":
		return runGet(rest, scope)
	case "edit", "view":
		return runTUI(rest, scope)
	case "list", "ls":
		return runList(rest, scope)
	case "delete", "rm":
		return runDelete(rest, scope)
	case "rename", "mv":
		return runRename(rest, scope)
	case "exec":
		return runExec(rest, scope)
	case "vault":
		return runVault(rest, scope)
	case "project":
		return runProject(rest, scope)
	case "env":
		return runEnv(rest, scope)
	case "import":
		return runImport(rest, scope)
	case "export":
		return runExport(rest, scope)
	case "audit":
		return runAudit(rest, scope)
	case "doctor":
		return runDoctor(rest, scope)
	case "web", "ui":
		return runWeb(rest)
	case "trust":
		return runTrust(rest, scope)
	case "untrust":
		return runUntrust(rest, scope)
	case "setup":
		return runSetup(rest)
	default:
		fmt.Fprintf(os.Stderr, "byn: unknown command %q\n", cmd)
		printUsage(os.Stderr)
		return 1
	}
}

// skipDiscoveryFor reports whether a subcommand should bypass the
// .byn walk. Management commands (trust, untrust, daemon, version,
// help, doctor) don't operate on a specific scope and would
// otherwise be blocked by an untrusted .byn from running at all.
func skipDiscoveryFor(cmd string) bool {
	switch cmd {
	case "trust", "untrust", "daemon", "start", "stop", "restart", "reload",
		"version", "--version", "-v",
		"help", "--help", "-h", "doctor", "web", "ui", "setup":
		return true
	}
	return false
}

// wantsHelp reports whether the subcommand's arg list looks like a
// help request: a "help" / "--help" / "-h" token anywhere in argv.
//
// Help is recognized in any position so all of these work:
//
//	byn put help
//	byn put --help
//	byn put -h
//
// If you legitimately want a secret literally named "help", use stdin
// redirection without the bare positional: `echo v | byn put help`
// is fine (the "help" is the value of NAME from positional arg
// parsing; this check looks for "help" as the FIRST positional). To be
// safe and unambiguous, the check matches "help" anywhere but only
// when there is no other positional-looking token after it.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	// A bare "help" token is a help request ONLY when it's the entire
	// argument set (single arg). Mixed with anything else, it's
	// treated as a real positional (so `byn put help` followed by
	// piped stdin still puts a secret named "help" if you really
	// want).
	if len(args) == 1 && args[0] == "help" {
		return true
	}
	return false
}

// printCommandHelp writes the help blob for cmd to stdout and returns
// the exit code (0 if found, 1 if unknown). Aliases are resolved via
// helpFor. Output is paged through $PAGER (default `less -RFX`) when
// stdout is a TTY, like man(1) and aws-cli.
func printCommandHelp(cmd string) int {
	if text := helpFor(cmd); text != "" {
		fprintPaged(os.Stdout, text)
		return 0
	}
	fmt.Fprintf(os.Stderr, "byn: no help available for %q\n", cmd)
	printUsage(os.Stderr)
	return 1
}

func printUsage(w *os.File) {
	fprintPaged(w, usageText())
}

func usageText() string {
	return fmt.Sprintf(`byn %s — secrets vault

Usage:
  byn                     Open the TUI editor (if a vault is initialized)
  byn <command> [args]
  byn <command> help      Detailed help for a command (also --help, -h)
  byn help <command>      Detailed help for a command

Global flags (work before or after the subcommand):
  --vault NAME               Target a vault (env: BYN_VAULT)
  --project NAME             Target a project (env: BYN_PROJECT)
  --env NAME                 Target an env (env: BYN_ENV)
  --json                     Agent mode: machine output; no interactive prompts
  --no-discovery             Skip the .byn parent-directory walk

Lifecycle:
  init                       Create a new vault (prompts for master password)
  start [--foreground]       Start the background daemon
  stop                       Stop the daemon
  restart [--foreground]     Restart the daemon
  reload                     Re-read ~/.byn/config without a restart
  status                     Daemon + vault state (also: --json)
  unlock                     Unlock the vault (prompts)
  lock [--all]               Lock the vault (or every vault with --all)
  passwd                     Change the master password (re-wraps the key)
  daemon install|uninstall   Auto-start the daemon on login

Structure (CRUD):
  vault list|delete|rename|passwd|init|unlock|lock
  project list|create|delete|rename
  env list|create|delete|rename

Env-vars (active scope):
  put <name>                 Store a secret (reads value from stdin)
  get, cat <name>            Print a secret to stdout (also: --json)
  list, ls [NAME|GLOB]       List secret names; with NAME/GLOB, grep-style
                             existence check (exit 0 if matched, else 1)
  delete, rm <name>          Remove a secret
  rename, mv <old> <new>     Rename a secret

Bulk I/O:
  import [PATH | -]          Import .env / .yaml / .json into active scope
  export                     Export active scope as .env / .yaml / .json

Execution:
  exec -- COMMAND [ARGS]     Run COMMAND with vault env-vars injected into its environment
  edit, view                 Open the modal TUI editor (vi-style keys)

Diagnostics:
  doctor                     Run self-checks (daemon, vaults, audit chain) (also: --json)
  audit tail [--lines N]     Print recent audit-log events (also: --json)
  audit verify               Re-walk the per-vault HMAC chain (also: --json)

Trust (.byn TOFU):
  trust [PATH]               Approve a .byn file (default: ./.byn)
  trust list                 List trusted paths (also: --json)
  untrust [PATH]             Revoke trust (default: ./.byn)

Misc:
  version                    Print version
  help [command]             Print this help, or detailed help for a command

For the full man page:  man byn
Home: https://github.com/sandeepbaynes/byn   ·   by Sandeep Baynes

Help / usage is paged through $PAGER (default: less -RFX) when stdout
is a TTY. Set BYN_NO_PAGER=1 or PAGER=cat to disable, or pipe to
cat for the same effect.
`, version)
}

// printVersion writes the version line plus build + author metadata.
func printVersion() {
	fmt.Printf("byn %s\n", version)
	if commit != "" || buildDate != "" {
		parts := commit
		if buildDate != "" {
			if parts != "" {
				parts += ", "
			}
			parts += "built " + buildDate
		}
		fmt.Printf("  %s\n", parts)
	}
	fmt.Printf("  by %s · %s\n", appAuthor, appHomepage)
}
