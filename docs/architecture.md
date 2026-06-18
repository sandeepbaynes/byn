# Architecture

How byn is organized, end to end.

---

## Process model

```
┌────────────────────────────────────┐
│ byn (CLI, thin IPC client)      │
│  • flag parsing + scope resolution │
│  • password prompt (raw-mode TTY)  │
│  • .byn discovery + TOFU check  │
│  • renders responses               │
└──────────────┬─────────────────────┘
               │  length-prefixed JSON envelope
               │  over Unix socket  (mode 0600, peer-UID checked)
               ▼
┌────────────────────────────────────┐
│ byn daemon                      │
│  • listener + dispatcher           │
│  • multi-vault state map           │
│  • per-vault audit logger          │
│  • persistent failed-unlock backoff│
│  • zero-copy mlock'd unwrap buffers│
└────────────────────────────────────┘
```

Two binaries, same code base, same `main` entrypoint
(`cmd/byn/main.go`). The daemon mode is invoked as
`byn daemon start --foreground`; the detached launcher re-execs
that. Everything else is the CLI.

**Why two processes:** the vault key only ever lives in the daemon's
memory. The CLI is short-lived; it never holds a decrypted key, and
it can't ask the daemon for one — only for *operations* on it. The
peer-UID enforcement on the socket means another user on the same
machine can't talk to your daemon.

**Connection model:** one envelope per connection. CLI dials, sends,
reads, closes. No multiplexing yet; not needed.

**Who the daemon runs as.** By default (privsep off) the daemon runs at *your*
UID. When you opt into privilege separation (`[security] privsep = true`, after
`byn setup`), the daemon runs as the dedicated **`_byn`** service account instead
— a different UID from you — so a same-(owner)-UID process can no longer ptrace
the daemon and lift the vault key. See [Privilege separation](#privilege-separation-three-uid-opt-in)
below and the [security model](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56)
for the threat reasoning and the honest ceiling.

---

## Scope hierarchy

```
vault                 # top-level container, separately encrypted
└── project           # logical group of envs
    └── env           # leaf scope (e.g. dev/staging/prod)
        └── entry     # one env-var (more kinds later: file)
```

Every command targets a `(vault, project, env)` triple, defaulting to
`(default, default, default)`.

**Inheritance.** A `get` against `env=staging` falls back to
`env=default` for entries that don't exist in staging. (Project and
vault are exact-match; no fallback above the env level.)

**Resolution precedence** (highest first):

1. CLI flag — `--vault NAME` / `--project NAME` / `--env NAME` (work
   before or after the subcommand)
2. Env var — `BYN_VAULT` / `BYN_PROJECT` / `BYN_ENV`
3. `.byn` discovery — see [`.byn` file + discovery](byn-file-format.md)
4. Daemon default — `default` everywhere

Computed by `cmd/byn/cliscope.go:preParseGlobals()` and merged with
discovery in `cmd/byn/main.go:run()`.

---

## Multi-vault state

`internal/daemon/daemon.go` holds:

```go
vaults map[string]*vaultEntry   // keyed by vault name
```

with `vaultEntry`:

```go
type vaultEntry struct {
    name       string
    store      *vault.Store    // SQLite + crypto handle
    auditor    *audit.Logger
    lastActive atomic.Int64
}
```

**Lifecycle:**

- `byn init` (vault.init op) → creates vault on disk + adopts entry.
- `byn unlock` (vault.unlock op) → opens the entry (lazy) +
  unwraps the key.
- `byn lock` (vault.lock op) → zeroes the key, keeps the entry
  (so the audit Logger handle stays alive).
- Per-vault idle timer — locks the vault after N minutes of
  inactivity (driven by `lastActive.Load()`).

**Why per-vault:** users may have multiple unrelated vaults (`work`,
`personal`, `client-X`). One unlock per vault, not per process. Vault A
being locked doesn't affect vault B.

---

## On-disk layout

See [File layout](file-layout.md) for the full reference. The data root is a
fixed per-machine location — `~/.byn` by default, or a system path
(`/var/lib/byn` // `/Library/Application Support/byn`, owned by `_byn`) once
provisioned for privilege separation. There is **no** runtime data-root env
override. Summary:

```
<data root>/
├── daemon.sock          # IPC socket (0600; runtime path when provisioned)
├── daemon.pid           # single-instance guard
├── daemon.log           # detached daemon's combined stdout/stderr
├── auth-state.json      # failed-unlock backoff (0600)
├── owner                # owner-UID record (provisioned only; "privsep on" marker)
├── trusted_byn.json  # TOFU records
├── audit/
│   └── <vault>/
│       └── YYYY-MM.log  # monthly rolled per-vault audit log (0600)
└── vaults/
    └── <vault>/
        ├── vault.db     # SQLite, mode 0600
        ├── wrapped.key  # Argon2id-wrapped vault key (0600)
        └── meta.json    # UUID + fingerprint of wrapped key (0600)
```

---

## Privilege separation (three-UID, opt-in)

byn can run under a **three-UID model** that separates the human, the daemon, and
exec children. It is **opt-in and off by default this release** (`[security]
privsep = true`, provisioned by `byn setup`). When off, byn behaves exactly as
before — the daemon and exec children run at your UID, and the same-UID env-sniff
/ daemon-ptrace holes remain open. The full threat reasoning, the off-state holes,
and the honest ceiling are in the [security model](security.md#privilege-separation-the-three-uid-model-opt-in-nu-56);
this section is the architecture sketch.

The three identities, all distinct (`owner ≠ _byn ≠ _byn-exec`):

| UID | Runs | Sees |
|---|---|---|
| **owner** (you) | the CLI, your shell, your agents | what your UID can already reach |
| **`_byn`** (service account) | the daemon (vault key in memory) | the vault key — but not the exec child's env |
| **`_byn-exec`** (service account) | `byn exec` children of a trusted, *pinned* `.byn` action | only the injected env vars, for the child's lifetime |

**Terminal-anchored exec spawn.** With privsep on, a trusted-`.byn` pinned
`byn exec` no longer runs the child in-process at your UID — but it is **not**
spawned server-side by the daemon either. The CLI spawns it **in your own shell's
process tree** through a small, root-owned **spawn helper** (`byn-exec-helper`,
setuid-root on macOS / `cap_setuid` file-capability on Linux), which drops to
`_byn-exec` and execs the pinned command. Spawning it in your shell's tree
(rather than under the daemon) is what lets the child **inherit your shell's macOS
TCC / Full Disk Access grant** — so `byn exec` works in `~/Documents`, iCloud,
etc. The injected secrets never pass through the owner-UID CLI: at authorization
the daemon mints a **one-time token**, and the helper redeems it directly from the
daemon (peercred-gated to root / `_byn-exec`) for the curated env. A
same-(owner)-UID **non-root** process then can't read that child's env — `ps -E`
on macOS, `/proc/<pid>/environ` on Linux (the kernel's cross-UID check denies the
read). Linux additionally sets `PR_SET_DUMPABLE=0` on the daemon and child; the
systemd unit keeps `NoNewPrivileges=no` **on purpose** so the scoped helper
retains its `cap_setuid`.

**Honest ceiling.** Privsep raises the bar to **root**. It does **not** defend
against root, `CAP_SYS_PTRACE`, or a root `task_for_pid` — those can still read
the daemon's or the child's memory/environ. macOS hardened-runtime protections
only take effect for a **Developer ID-signed** build (unsigned local builds don't
get them). Ad-hoc `byn exec` (no pinned `.byn`) still runs at your UID even with
privsep on.

**Fail-closed.** Privsep enabled but **not** provisioned errors out ("run `sudo
byn setup`") — it never silently downgrades to running the daemon or exec child at
the owner UID.

---

## SQLite schema (v4, STRICT)

```sql
-- Meta key-value table; schema_version, audit_chain_seed,
-- audit_chain_head, entries_state_hash, totp_secret_v1 (reserved).
meta(key TEXT PRIMARY KEY, value TEXT) STRICT

-- Project rows; default project created at init.
projects(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT

-- Env rows; default env per project created at init.
envs(
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (project_id, name)
) STRICT

-- One row per env-var entry. Value is XChaCha20-Poly1305 ciphertext
-- with random 24-byte nonce; AAD = vault_id || 0x1F || kind || 0x1F || name.
-- require_2fa is reserved for the future TOTP gate.
entries(
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    env_id INTEGER NOT NULL REFERENCES envs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('env_var','file')),
    name TEXT NOT NULL,
    value BLOB NOT NULL,
    aad_version INTEGER NOT NULL DEFAULT 1,
    deleted_at TEXT,
    require_2fa INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (project_id, env_id, name)
) STRICT

-- Historical revisions for entry versioning. Append-only.
entry_versions(
    id INTEGER PRIMARY KEY,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    version_no INTEGER NOT NULL,
    value BLOB NOT NULL,
    aad_version INTEGER NOT NULL,
    op TEXT NOT NULL CHECK (op IN ('put','rename','delete')),
    op_meta TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (entry_id, version_no)
) STRICT

-- Portal passkey credentials (WebAuthn). All columns are non-secret.
passkey(
    id INTEGER PRIMARY KEY,
    credential_id BLOB NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    aaguid BLOB, transports TEXT NOT NULL DEFAULT '', label TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,   -- WebAuthn BE flag (must round-trip)
    backup_state INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT

-- PRF-derived second wrapping of the vault key, one row per credential (cold
-- unlock). Revoking the credential cascades here; the KEK = HKDF(prfOut) that
-- unwraps wrapped_vault_key is computed in the browser and never stored.
passkey_unlock(
    credential_id BLOB PRIMARY KEY REFERENCES passkey(credential_id) ON DELETE CASCADE,
    prf_salt BLOB NOT NULL,
    wrapped_vault_key BLOB NOT NULL,
    hkdf_info_version INTEGER NOT NULL DEFAULT 1,
    aead_alg TEXT NOT NULL DEFAULT 'xchacha20poly1305',
    label TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
) STRICT

-- File-content secrets (reserved; data-plane CRUD not yet shipped).
file_meta(...) STRICT
```

Foreign keys are enforced (`PRAGMA foreign_keys = ON`). The whole DB
opens with WAL journaling.

**Why STRICT tables:** SQLite's type affinity is famously loose. STRICT
mode makes every column type-checked at write time, so we catch
programmer errors instead of corrupting the row.

---

## IPC envelope

`internal/ipc/types.go`:

```go
type Envelope struct {
    V    uint            // protocol version (negotiated against ProtocolMin..ProtocolMax)
    ID   string          // 16-byte hex request id
    Op   Op              // string op (e.g. "vault.unlock", "put", "audit.tail")
    Req  json.RawMessage // populated on request
    Resp json.RawMessage // populated on response
    Err  *ErrMsg         // populated on error response
}

type ErrMsg struct {
    Code    ErrCode // stable code like "wrong_password", "locked", "rate_limited"
    Message string
    Recover string  // suggested recovery command, e.g. "byn unlock"
}
```

**Wire format:** 4-byte big-endian length prefix + JSON. See
`internal/ipc/frame.go`.

**Op naming:** `<noun>.<verb>` for namespaced (`vault.init`,
`project.create`, `audit.tail`); flat for the env-var data plane
(`put`, `get`, `list`, `delete`, `rename`) since they're the most
common.

**Error codes** (stable string identifiers — CLI exit code 3 means
"daemon returned a typed error"):

| Code | Meaning |
|---|---|
| `unknown_op` | Daemon doesn't recognize op |
| `bad_request` | Body fails decode |
| `unsupported_version` | Protocol mismatch |
| `binary_too_old` | CLI older than daemon's `ProtocolMin` |
| `locked` | Vault not unlocked |
| `wrong_password` | Generic unlock failure (existence-oracle defense) |
| `rate_limited` | Failed-unlock backoff hit |
| `already_init` | Vault already exists |
| `not_init` | Vault not present |
| `vault_not_found` / `vault_exists` | Multi-vault management |
| `bad_name` | Project/env/vault name fails validation |
| `not_found` | Entry, project, or env not found |
| `already_exists` | Create-only collision |
| `project_not_found` / `project_exists` | Project CRUD |
| `env_not_found` / `env_exists` | Env CRUD |
| `internal` | Daemon-side bug; check logs |

---

## Request flow (example: `byn put DB_URL`)

1. CLI starts: `cmd/byn/main.go:run()` parses `os.Args`.
2. `jsonModeFromArgs` + `noDiscoveryFromArgs` detect agent mode and
   `--no-discovery`.
3. `preParseGlobals` extracts `--vault/--project/--env` from anywhere
   in argv; conflicts are a hard error.
4. `.byn` discovery walks parents from CWD; first hit is hashed;
   `isTrusted` checks against `trusted_byn.json`. Untrusted +
   agent mode = hard fail; untrusted + TTY = prompt; trusted = apply.
5. Resolved scope = CLI flag > env var > discovered > daemon default.
6. `runPut` reads the value from stdin (never argv).
7. `newClient(dir).Call(OpPut, PutReq{Scope, Name, Value, CreateOnly}, …)`
   dials `~/.byn/daemon.sock`, writes one envelope, reads one.
8. Daemon's `handleConn → dispatch → handlePut`:
   - Looks up vault by `Scope.Vault` (case-sensitive after
     `vault.ValidateVaultName`).
   - `entry.touch()` updates idle timer.
   - `entry.store.Put(scope.Project, scope.Env, name, value, …)`
     encrypts the value (XChaCha20-Poly1305 + AAD-binding) and writes
     the row.
   - `auditEmit` appends a chained audit event:
     `{Project, Env, Kind, EntryName, Op, Outcome, CallerUID, CallerPID, HMACChain}`.
9. Response = `{Op: "put", Resp: PutResp{}}`.
10. CLI prints the hint (`Stored "DB_URL" in default/default/default.`)
    via `hintf()` (unless `BYN_HINTS=0` or stderr non-TTY).
11. Exit 0.

---

## Audit log

Per-vault append-only NDJSON files under `~/.byn/audit/<vault>/`.
Each event is one JSON line; files roll monthly (`2026-06.log`).

**Chain:** each event carries an `hmac_chain` field, computed as
`HMAC-SHA256(seed, prev_chain || event_bytes_canonical)`. `seed` is
32 random bytes stored in the vault's `meta.audit_chain_seed` key.
The head (latest hash) is stored in `meta.audit_chain_head` so the
daemon can resume on cold start without re-walking.

**Verification:** `byn audit verify` re-walks the log,
recomputing the chain and checking each line's `hmac_chain` matches.
First mismatch → BadIndex >= 0 → exit code 3 + treat-as-compromised
message. Read by `internal/audit/audit.go:VerifyChain`.

**What's in an event:**

```
{
  "ts":         <unix nanos>,
  "vault_id":   <UUID from meta.json>,
  "vault_name": <human-readable>,
  "project":    <if op scoped>,
  "env":        <if op scoped>,
  "kind":       "env_var" | "file",
  "entry_name": <plain-text name; forensics-friendly>,
  "op":         <ipc op string>,
  "outcome":    "ok" | "denied" | "not_found" | "error",
  "caller_uid": <socket peer uid>,
  "caller_pid": <socket peer pid, where the OS surfaces it>,
  "error_code": <if outcome != ok>,
  "hmac_chain": <hex>
}
```

**Why plain-text names** (not hashed): trade-off documented in
internal design notes. Forensic value of
"DB_URL was accessed" beats the marginal confidentiality win of
hashing.

---

## Crypto stack

| Layer | Primitive |
|---|---|
| Row value | XChaCha20-Poly1305, vault key, random 24-byte nonce per row, AAD = `vault_id ‖ 0x1F ‖ kind ‖ 0x1F ‖ name` |
| Vault-key wrapping | Argon2id(password, salt) → wrapping key → XChaCha20-Poly1305, AAD = full header bytes (binds salt + Argon2 params + version) |
| Hardware-key wrapping | macOS Secure Enclave (ECIES via Security.framework) or Linux TPM2, with a software fallback. Wired but gated on entitlements (Slice 1.3) |
| Audit chain | HMAC-SHA256, 32-byte seed from vault meta |
| Failed-unlock state | unsigned today; HMAC-signed in deferred hardening |
| Trust file | UNIX perms today; HMAC-signed in deferred hardening (see internal design notes) |

See [security.md](security.md) for parameters (Argon2id memory cost,
time cost), AAD-binding rationale, and threat model.

---

## CLI package layout (`cmd/byn/`)

| File | What it does |
|---|---|
| `main.go` | Subcommand dispatcher; agent-mode detection; discovery wiring; usage |
| `cliscope.go` | `cliScope` struct + hybrid pre-parser + conflict detection |
| `discovery.go` | `.byn` walk + TOFU trust store |
| `cmd_daemon.go` | `daemon {start,stop,status}` + `status [--json]` |
| `cmd_vault.go` | `init`, `unlock`, `lock`, `put`, `get`, `list`, `delete`, `rename` |
| `cmd_vault_crud.go` | `vault {list,delete,init,unlock,lock}` (top-level aliases) |
| `cmd_project.go` | `project {create,list,delete,rename}` |
| `cmd_env.go` | `env {create,list,delete,rename}` |
| `cmd_exec.go` | `exec -- COMMAND` (in-process `syscall.Exec` env injection; with privsep on, a trusted-pinned exec is spawned daemon-side as `_byn-exec`) |
| `cmd_setup.go` | `setup [--uninstall [--purge]]` — one-sudo privsep provisioning |
| `cmd_migrate.go` | `migrate [--from PATH] [--force]` — relocate vs import |
| `cmd_import.go` | `import` from .env/.yaml/.json |
| `cmd_export.go` | `export` to .env/.yaml/.json |
| `cmd_audit.go` | `audit {tail,verify}` |
| `cmd_doctor.go` | `doctor [--json]` |
| `cmd_trust.go` | `trust [PATH]`, `trust list`, `untrust [PATH]` |
| `cmd_tui.go` | Modal vi-style TUI (env-vars only for default scope) |
| `common.go` | Exit codes, IPC client factory, `handleCallError` |
| `color.go` | ANSI color helpers with NO_COLOR/FORCE_COLOR detection |
| `hints.go` | `hintf` (gated by `BYN_HINTS`) |
| `help_text.go` | AWS-CLI-style per-command help blobs |
| `pager.go` | `$PAGER` integration for help (default `less -RFX`) |

---

## Daemon package layout (`internal/daemon/`)

| File | What it does |
|---|---|
| `daemon.go` | Lifecycle: listener bind, pidfile, vault map, peer-UID enforcement |
| `dispatch.go` | Op routing + status/vault/project/env/data-plane handlers |
| `dispatch_audit_doctor.go` | `audit.tail`, `audit.verify`, `doctor` handlers |
| `peercred*.go` | `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) |

---

## Other internal packages

| Package | Role |
|---|---|
| `internal/vault` | Store API; SQLite open/init/migrate; scoped CRUD; encryption |
| `internal/vault/crypto` | Argon2id wrap, AEAD seal/open |
| `internal/ipc` | Wire types, framing, client |
| `internal/audit` | HMAC-chained log; Tail/Append/VerifyChain |
| `internal/auth` | Raw-mode password prompt; persistent failed-unlock backoff |
| `internal/secmem` | `mlock`'d buffers for sensitive workspace |
| `internal/hwkey` | macOS SE / Linux TPM2 / software fallback (provider interface) |
| `internal/passkey` | WebAuthn relying party — register/assert ceremonies + PRF→KEK derivation for portal passkey unlock |
| `internal/ui` | daemon-embedded browser portal (loopback HTTP; scope tree, entries, passkey unlock) |
| `internal/paths` | resolves the active data root + socket path (legacy `~/.byn` vs provisioned system path); owner-record lookup |
| `internal/privsep` | three-UID model: owner-record read/write, service-user resolution, the `_byn-exec` spawn path |
| `internal/setup` | `byn setup` provisioning + teardown (service users, system service, spawn helper, owner record) |
| `internal/migrate` | `byn migrate` relocate vs import (verify-without-password, atomic adopt) |
| `internal/trust` | `.byn` TOFU store + fp-MAC (machine) / vk-MAC (vault-key) record verification |
| `internal/machineid` | stable per-machine identifier keying the trust fp-MAC (never touches the vault key) |
| `internal/shim` | (reserved; planned — see roadmap) |
| `internal/acl` | (reserved; planned) |

---

## Related

- [Security model](security.md) — the *why* behind the crypto choices.
- [`.byn` + discovery](byn-file-format.md) — the spec for the
  scope-discovery file and TOFU.
- [File layout](file-layout.md) — every file on disk, its purpose, its mode.
- [CLI reference](cli-reference.md) — every command + flag + exit code.
