# byn

**v0.0.1** · by Sandeep Baynes · [github.com/sandeepbaynes/byn](https://github.com/sandeepbaynes/byn) ·
Source-available (BUSL-1.1)

Secure secrets vault and credential management with a local daemon and a
thin CLI client. Pre-release, under active development.

Built for a machine that's **owned by you but operated by many** — coding
agents, bots, and scripts all run under your account, none of them you.
byn keeps secret *values* out of their reach while transparently delivering
them to the tools that legitimately need them.

## Install

```sh
# Homebrew or the install script — recommended; both put `byn` on your PATH.
# (Available with the first tagged release.)
brew install sandeepbaynes/tap/byn
curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh

# With the Go toolchain — works today, builds from source.
go install github.com/sandeepbaynes/byn/cmd/byn@latest
```

**New to byn? Follow the [5-minute quickstart](docs/quickstart.md)** — install →
daemon → vault → first secret → portal.

> `go install` does **not** modify your PATH. Ensure `$(go env GOPATH)/bin`
> (usually `~/go/bin`) is on it — e.g. add `export PATH="$HOME/go/bin:$PATH"` to
> your shell rc. Homebrew and the install script handle this for you.

> **⚠️ Early access — the install path will change.** byn is pre-1.0 and
> currently installs from `github.com/sandeepbaynes/byn`. Once the project's
> own domain is in place, the canonical Go module path (and the Homebrew tap)
> will move to a **branded path on that domain**. You can install and use byn
> today — just be aware you'll re-point to the new path when it lands. Existing
> installs keep working; they simply won't pull updates from the old path once
> it moves. Watch the
> [releases](https://github.com/sandeepbaynes/byn/releases) for the switch.

Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Sign off your
commits with `git commit -s` (Developer Certificate of Origin) — no CLA.

Then:

```sh
byn start
byn init           # create your first vault
byn unlock
byn put API_KEY    # value is read from stdin
byn ls             # names are always listable; values stay encrypted
```

> The CLI is an IPC client only. All business logic — vault, encryption,
> ACLs, audit, shims — lives in the daemon.
>
> **Contracts:** [spec.md](docs/spec.md) is the authoritative behavior
> contract — every invariant lives there. Read it first when changing
> anything.
>
> **Explanations** live in [`docs/`](docs/):
> [architecture](docs/architecture.md) · [security model](docs/security.md) ·
> [CLI reference](docs/cli-reference.md) ·
> [`.byn` format](docs/byn-file-format.md) ·
> [file layout](docs/file-layout.md) · [glossary](docs/glossary.md) ·
> [troubleshooting](docs/troubleshooting.md) ·
> [TUI design](docs/tui-design.md) ·
> [integrations](docs/integrations/)

---

## Platform support

byn targets **macOS and Linux** today (Go 1.25+, pure-Go binary). **Windows is
not yet supported** — the daemon's Unix-socket IPC + peer-UID enforcement, the
`syscall.Exec` injection path, the machine fingerprint, and `mlock` / file-mode
hardening all assume a Unix host. A Windows port (named-pipe IPC, token/SID
peer-auth, `CreateProcess` exec, WMI fingerprint, ACL hardening) is a tracked,
**contribution-welcome** roadmap item — the platform-specific pieces sit behind
interfaces, so it can land without touching the core. Windows Hello already
supports the WebAuthn PRF the portal unlock uses, so that part would come along.

---

## Status

What works today (post Phase 1–6 overnight push, 2026-06-02):

- Encrypted multi-vault store under `~/.byn/vaults/<name>/` (per-vault SQLite + Argon2id-wrapped key)
- Multi-vault daemon model: many vaults can be unlocked simultaneously, each with its own idle timer
- Per-vault `vault → project → env` scope hierarchy with inheritance (non-default env falls back to default)
- Daemon over Unix socket (`~/.byn/daemon.sock`, mode `0600`, peer-UID enforced)
- CLI lifecycle: `init`, `unlock`, `lock`, `daemon {start,stop,status}`, `status [--json]`
- CLI structure CRUD: `vault {list,delete,init,unlock,lock}`, `project {list,create,delete,rename}`, `env {list,create,delete,rename}` — all `list`s accept `--json`
- CLI env-var ops (per active scope): `put`, `get [--json]`, `list [--json]`, `delete`, `rename`, `cat`/`ls`/`rm`/`mv` aliases
- Bulk I/O: `import` from `.env`/`.yaml`/`.json` (file path, stdin, or `--format`-forced), `export` to same formats (stdout or `--output PATH`)
- `byn exec -- CMD` — replace-in-place execution that injects vault env-vars into the child's environ via `syscall.Exec`. Values never appear in shell history, argv, or scrollback.
- Hybrid scope-flag positioning: `--vault`/`--project`/`--env` work before OR after the subcommand; conflicting duplicates are a hard error; env-var fallbacks `BYN_VAULT`/`BYN_PROJECT`/`BYN_ENV`
- Modal vi-style TUI for the default scope (`byn` with no args, or `byn edit`)
- Browser admin portal (`byn web`) — daemon-embedded, loopback-only at
  `localhost:2967` (configurable); password **or passkey / Touch ID unlock**
  (WebAuthn PRF on macOS; enroll/revoke from the portal, password stays the
  recovery root); session/CSRF; browse the scope tree, view/edit entries, reveal
  values (audited). Same vault as the CLI/TUI.
- HMAC-chained audit log per vault (append-only, plain-text names for forensics)
- AWS-CLI-style per-command help (`byn <cmd> help`, `--help`, or `byn help <cmd>`); `man byn`
- Persistent failed-unlock rate limiter (survives daemon restart)
- IDE integration docs: see [`docs/integrations/`](docs/integrations/) for VS Code, JetBrains, Eclipse, and AI coding agents

Not yet:

- macOS Secure Enclave / Linux TPM2 wrapping (skeletons in place; tests skip without entitlements)
- launchd/systemd auto-install
- Idle re-lock UI polish
- FUSE-mounted file secrets, shims, ACLs, cloud sync
- Neovim-style TUI redesign with left rail navigation across vault/project/env/files (the existing modal TUI is env-var-only for the default scope)

---

## Architecture

```
┌──────────────┐   length-prefixed JSON    ┌────────────────────────────┐
│ byn (CLI)    │ ◄──────────────────────►  │ byn daemon                 │
│  flag-parse  │     Unix socket           │                            │
│  password    │     mode 0600             │ ┌────────────────────────┐ │
│  prompt      │     peer UID checked      │ │ in-memory vault key    │ │
│  formatted   │                           │ │ (zeroed on Lock)       │ │
│  errors      │                           │ └────────────┬───────────┘ │
└──────────────┘                           │              │             │
                                           │ ┌────────────▼───────────┐ │
                                           │ │ vault (SQLite, WAL)    │ │
                                           │ │  • names: plaintext    │ │
                                           │ │  • values: ciphertext  │ │
                                           │ │    (XChaCha20-Poly1305)│ │
                                           │ └────────────────────────┘ │
                                           │ ┌────────────────────────┐ │
                                           │ │ wrapped.key on disk    │ │
                                           │ │  Argon2id(password)    │ │
                                           │ │  → AAD-bound header    │ │
                                           │ │  → XChaCha20-Poly1305  │ │
                                           │ └────────────────────────┘ │
                                           │ ┌────────────────────────┐ │
                                           │ │ auth-state.json        │ │
                                           │ │  failed-unlock backoff │ │
                                           │ └────────────────────────┘ │
                                           └────────────────────────────┘
```

**Daemon lifetime is per-user.** The pidfile (`daemon.pid`) prevents
double-start; a stale pidfile is detected (signal-0 probe) and replaced.

**Connection model: one envelope per connection.** Each CLI invocation
dials the socket, sends one request, reads one response, closes.
Long-lived multiplexed connections come later (web UI).

**Crypto stack:**

| Layer | Primitive |
|---|---|
| Row value encryption | XChaCha20-Poly1305, vault-key keyed, per-row 24-byte random nonce, AAD = version byte |
| Vault-key wrapping | Argon2id(password, salt) → wrapping key → XChaCha20-Poly1305, AAD = full header (binds salt + params against tampering) |
| Hardware-key wrapping | macOS Secure Enclave (ECIES via Security.framework) / Linux TPM2 / software fallback — *Slice 1.3 wires this in* |

Why not the `age` file format for rows: it's a file container with header
framing optimized for at-rest blobs; per-row overhead is wasted. Same
underlying AEAD. The age format returns in Phase 6 for vault export/import.

---

## Project layout

```
byn/
├── cmd/byn/                  # CLI (thin IPC client)
│   ├── main.go                  #   subcommand dispatcher + exit codes
│   ├── common.go                #   shared helpers (dir resolution, error mapping)
│   ├── cmd_vault.go             #   init/unlock/lock/put/get/list/delete/rename
│   └── cmd_daemon.go            #   daemon start/stop/status
├── internal/
│   ├── vault/                   # SQLite-backed encrypted store
│   │   ├── store.go             #   Open/Init/Unlock/Lock/Put/Get/List/Delete/Rename
│   │   ├── schema.go            #   schema, migrations, WAL setup
│   │   └── crypto/              # Symmetric primitives
│   │       ├── wrap.go          #   Argon2id wrap/unwrap with AAD-bound header
│   │       └── encrypt.go       #   row AEAD (XChaCha20-Poly1305)
│   ├── ipc/                     # Wire protocol
│   │   ├── types.go             #   envelopes, ops, error codes
│   │   ├── frame.go             #   length-prefixed JSON
│   │   ├── conn.go              #   envelope helpers
│   │   └── client.go            #   Unix-socket client
│   ├── daemon/                  # Socket server + state machine
│   │   ├── daemon.go            #   listener, pidfile, lifecycle
│   │   ├── dispatch.go          #   request routing + op handlers
│   │   ├── peercred.go          #   peer UID interface
│   │   └── peercred_{darwin,linux}.go
│   ├── auth/                    # Password prompt + rate limiter
│   │   ├── prompt.go            #   golang.org/x/term raw-mode read
│   │   └── ratelimit.go         #   persistent exponential backoff
│   └── hwkey/                   # Hardware-key Provider interface
│       ├── provider.go          #   Provider interface + sentinel errors
│       ├── software.go          #   file-backed fallback
│       ├── macos.go             #   Secure Enclave (CGo, build-tag darwin)
│       └── linux.go             #   TPM2 stub (build-tag linux)
└── tests/integration/           # End-to-end against the real binary
```

---

## Build, test, lint

Requires Go 1.25+ (dependency floor). (Developed against 1.26.)

```sh
make build              # → bin/byn
make test               # unit tests, race detector on
make test-integration   # builds the binary, drives it end-to-end
make lint               # golangci-lint (v2 config in .golangci.yml)
make cover              # coverage report → coverage.html
make clean
```

Single test:

```sh
go test -race -run TestPutGetRoundtrip ./internal/daemon/...
```

A short manual smoke covering the golden path:

```sh
make build

export BYN_DIR=/tmp/byn-smoke

bin/byn start
bin/byn status                           # → uninitialized
bin/byn init                             # prompts for password twice
bin/byn unlock                           # prompts once
echo 's3cr3t-value' | bin/byn put my-key
bin/byn get my-key                       # → s3cr3t-value
bin/byn list                             # → my-key
bin/byn lock
bin/byn get my-key                       # → error: vault is locked
bin/byn stop
```

For non-interactive (CI, scripts) use `--password-stdin`:

```sh
echo 'master-password' | bin/byn init --password-stdin
echo 'master-password' | bin/byn unlock --password-stdin
```

---

## Commands

### Global scope flags

These work **before or after** the subcommand. Conflicting duplicates
are a hard error. Env-var fallbacks shown in `( )`.

| Flag | Env var | Default |
|---|---|---|
| `--vault NAME` | `BYN_VAULT` | `default` |
| `--project NAME` | `BYN_PROJECT` | `default` |
| `--env NAME` | `BYN_ENV` | `default` |

### Lifecycle

| Command | Action |
|---|---|
| `byn init [--password-stdin]` | Create a new vault |
| `byn unlock [--password-stdin]` | Unlock the vault for this daemon session |
| `byn lock` | Zero the in-memory vault key |
| `byn start [--foreground]` | Start the daemon (detached by default) |
| `byn stop` | Stop the daemon (SIGTERM via pidfile) |
| `byn restart [--foreground]` | Restart the daemon |
| `byn reload` | Re-read `~/.byn/config` without a restart |
| `byn status [--json]` | Daemon + vault state |
| `byn daemon install\|uninstall` | Auto-start the daemon on login |

### Structure (vault → project → env)

| Command | Action |
|---|---|
| `byn vault list [--json]` | List vaults on disk |
| `byn vault delete NAME` | Remove a vault (refuses `default`) |
| `byn project list [--json]` | List projects in active vault |
| `byn project create NAME` | Create a project (and its default env) |
| `byn project delete NAME` | Cascade-delete project + envs + entries |
| `byn project rename OLD NEW` | Rename |
| `byn env list [--json]` | List envs in active project |
| `byn env create NAME` | Create a non-default env |
| `byn env delete NAME` | Remove a non-default env |
| `byn env rename OLD NEW` | Rename |

### Env-vars (active scope)

| Command | Action |
|---|---|
| `byn put <name> [--create-only]` | Store a secret (reads value from stdin) |
| `byn get <name> [--json]` | Print decrypted value to stdout |
| `byn list [--json]` / `ls` | List secret names (allowed while locked) |
| `byn delete <name>` / `rm` | Remove a secret (allowed while locked) |
| `byn rename <old> <new>` / `mv` | Move a secret to a new name |

### Bulk I/O

| Command | Action |
|---|---|
| `byn import [--format env|yaml|json] [--dry-run] [--skip-existing \| --replace [--yes]] [PATH \| -]` | Bulk-load env-vars into the active scope; default merges, `--skip-existing` adds only, `--replace` wipes scope first (requires `--yes` in non-TTY) |
| `byn export [--format env|yaml|json] [--output PATH]` | Dump active scope as flat key→value document |

### Execution

| Command | Action |
|---|---|
| `byn exec -- COMMAND [ARGS]` | `syscall.Exec` `COMMAND` with vault env-vars injected; values never appear in shell history, argv, or scrollback |
| `byn edit` / `view` / `byn` (no args) | Open the responsive bubbletea TUI (left-rail nav, vi-style draft semantics, undo/redo, clipboard, inheritance badges, scope picker). Honors `--vault`/`--project`/`--env` for pre-positioning. See [`docs/tui-design.md`](docs/tui-design.md). |

### Diagnostics

| Command | Action |
|---|---|
| `byn doctor [--json]` | Daemon/vault/schema/audit-chain self-checks; non-zero exit on any fail |
| `byn audit tail [--lines N] [--json]` | Print recent audit-log events for the active vault |
| `byn audit verify [--json]` | Re-walk the HMAC chain; exit 3 if broken |

### Trust (`.byn` TOFU)

| Command | Action |
|---|---|
| `byn trust [PATH]` | Approve a `.byn` file (default: `./.byn`) |
| `byn trust list [--json]` | List trusted paths |
| `byn untrust [PATH]` | Revoke trust (default: `./.byn`) |

See [`docs/byn-file-format.md`](docs/byn-file-format.md) for the discovery walk and TOFU semantics.

### Misc

| Command | Action |
|---|---|
| `byn version` | Print the binary version |
| `byn help [command]` | Per-command help blob; also `byn <cmd> --help` |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error (bad usage, runtime failure) |
| 2 | Daemon unreachable — recovery hint printed to stderr |
| 3 | Daemon returned a typed error (wrong password, not found, locked, etc.) |

Errors include an actionable recovery line on stderr:

```
$ byn get foo
Error: vault is locked
Try: byn unlock
```

---

## Configuration

Environment:

| Var | Default | Purpose |
|---|---|---|
| `BYN_DIR` | `~/.byn` | Daemon data directory |

Files inside `BYN_DIR`:

| File | Description |
|---|---|
| `vault.db` | SQLite database, mode `0600` |
| `wrapped.key` | Argon2id-wrapped vault key blob, mode `0600` |
| `daemon.sock` | Unix domain socket, mode `0600`, peer-UID enforced |
| `daemon.pid` | Pidfile (single-instance guard) |
| `daemon.log` | Daemon's combined stdout/stderr when started detached |
| `auth-state.json` | Failed-unlock backoff state, mode `0600` |

The daemon binds the socket at `<BYN_DIR>/daemon.sock`. On macOS,
`sun_path` is capped at 104 bytes — keep `BYN_DIR` short.

---

## Roadmap

Highlights of what's next:

- **Release readiness** — daemon auto-start (launchd/systemd, `byn daemon install`), quickstart guide
- **Phase 3** — shim engine + `aws`/`gcloud`/etc. credential injection + tamper-evident audit log
- **Phase 4–7** — ACLs, FUSE, cloud sync, enterprise features

---

## License

**Business Source License 1.1 (BUSL-1.1)** — source-available, *not* OSI
"open source". You may use, modify, and self-host byn for any purpose,
including internal and commercial use at work. The one restriction: you may
not offer byn to third parties as a competing hosted/managed
secrets-management service. Each released version automatically converts to
**Apache-2.0** four years after its release. See [`LICENSE`](LICENSE) for the
exact terms, including the Additional Use Grant.

byn is **open-core**: this repository is the free, source-available base. Paid
enterprise features (multi-user management, team ACLs / sharing, SSO, audit
export & compliance) live in a separate repository under commercial terms.
