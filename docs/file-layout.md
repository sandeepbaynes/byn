# File layout

Every file byn writes, where it lives, what it contains, and what
mode protects it.

The **data root** is a single per-machine location. There is **no runtime
override** — the data-root environment variable that older byn versions honored
has been removed (a repointable data root was attack surface). Where the root
lives depends on whether the machine has been
provisioned for privilege separation:

- **Provisioned** (`byn setup` run, privsep on): a fixed **system path** owned by
  the `_byn` service account, mode `0700`:
  - Linux: `/var/lib/byn` (the systemd unit's `StateDirectory=byn`)
  - macOS: `/Library/Application Support/byn`
- **Unprovisioned** (default, privsep off): the **legacy** per-user path `~/.byn`,
  owned by you, mode `0700` — today's behavior, unchanged.

The layout below is identical under both roots; only the location and owning UID
differ. To keep work and personal credentials apart, use **multiple vaults** in
the one daemon (`byn init <name>`), **not** multiple data dirs.

---

```
<data root>/                       # ~/.byn (legacy) or the system path (provisioned)
├── daemon.sock                    # Unix socket; IPC (legacy root only — see note)
├── daemon.pid                     # Single-instance pidfile
├── daemon.log                     # Detached daemon's stdout+stderr
├── auth-state.json                # Persistent failed-unlock backoff
├── owner                          # Owner-UID record (provisioned only; the "privsep on" marker)
├── trusted_byn.json            # TOFU records for .byn files
├── audit/
│   └── <vault>/
│       └── YYYY-MM.log            # Monthly-rolled per-vault audit log
└── vaults/
    └── <vault>/
        ├── vault.db               # SQLite (encrypted values)
        ├── vault.db-wal           # SQLite WAL journal (transient)
        ├── vault.db-shm           # SQLite shared-memory (transient)
        ├── wrapped.key            # Argon2id-wrapped vault key
        └── meta.json              # Vault UUID + wrapped-key fingerprint
```

---

## Daemon files

### `daemon.sock`

| | |
|---|---|
| Mode | `0600` |
| Owner | daemon's UID |
| Created by | `internal/daemon/daemon.go:Start` |

Unix-domain socket. Every CLI invocation dials it. Peer UID is
checked on every connect; mismatched UIDs are closed immediately.

**Where it lives.** On the **legacy** `~/.byn` root the socket sits inside the
data dir (shown above). When the machine is **provisioned** for privilege
separation, the daemon runs as `_byn` and the data root is `_byn`-owned `0700`,
so the socket can't live inside it (you'd be unable to connect). It binds instead
to an **owner-traversable runtime path**; the daemon's bind side and the CLI's
connect side resolve the same location, so they can never disagree. The peer-UID
check still allowlists exactly the owner.

**macOS caveat:** `sun_path` is capped at 104 bytes, so the socket path must stay
short. The fixed data-root paths are chosen to fit; the test-only data-dir seam
(compiled in only under the `byntest` build tag) uses `/tmp/byn-it-XXXX` for this
reason.

### `owner`

| | |
|---|---|
| Mode | `0600` |
| Owner | `_byn` (provisioned root only) |
| Format | JSON: the allowlisted owner UID recorded by `byn setup` from `SUDO_UID` |
| Created by | `byn setup` (`internal/privsep:WriteOwnerRecord`) |

Present only in a **provisioned** system root. Its existence is the
authoritative "this machine is provisioned for privsep" marker, and it names the
single UID the daemon allowlists on its peercred-gated socket. `sudo byn setup
--uninstall` removes it; the vault stays intact. See
[Migration & setup](migration.md).

### `daemon.pid`

| | |
|---|---|
| Mode | `0600` |
| Owner | daemon's UID |
| Created by | `internal/daemon/daemon.go:writePidfile` |

Plain text decimal PID. On `daemon start`, a stale pidfile is
detected via signal-0 (`kill(pid, 0)`); if the process is gone, it's
replaced.

### `daemon.log`

| | |
|---|---|
| Mode | `0600` |
| Owner | daemon's UID |
| Created by | `cmd/byn/cmd_daemon.go:runDaemonDetached` |

Combined stdout/stderr of the detached daemon. Append-only. Rotation
is your job (logrotate, manual, etc.).

### `auth-state.json`

| | |
|---|---|
| Mode | `0600` |
| Owner | daemon's UID |
| Format | JSON: `{"failures": N, "next_allowed": "RFC3339 ts"}` |
| Created by | `internal/auth/ratelimit.go:persist` |

Persistent failed-unlock backoff. Survives daemon restart so an
attacker can't `daemon stop && start` to reset the timer.

**Hardening:** not currently signed; an attacker with write access
to `~/.byn` can reset the counter. Deferred — see
[security.md](security.md).

---

## Trust file

### `trusted_byn.json`

| | |
|---|---|
| Mode | `0600` |
| Owner | user (created by the CLI on first `byn trust`) |
| Format | JSON: `{"records": [{"path": "...", "sha256": "..."}, ...]}` |
| Created by | `cmd/byn/discovery.go:saveTrustStore` |

TOFU records for `.byn` files. See
[`.byn` file format](byn-file-format.md) for the lookup
algorithm and TOFU semantics.

**Hardening:** integrity protection (HMAC) is designed and deferred.

---

## Audit logs

### `audit/<vault>/YYYY-MM.log`

| | |
|---|---|
| Mode | `0600` |
| Owner | daemon's UID |
| Format | NDJSON (one event per line) |
| Created by | `internal/audit/audit.go:appendLine` |

Append-only. New month → new file. The latest file is the only one
actively written; older months are immutable historical records.

Each line is an `audit.Event` (see [architecture.md](architecture.md#audit-log)).

**HMAC chain:** every line's `hmac_chain` field depends on the
previous line's. Truncation, insertion, deletion, or modification all
fail `byn audit verify`.

The HMAC seed lives in the per-vault `meta.audit_chain_seed` SQLite
meta key. Both seed and head are accessible while the vault is locked
(both are in the unencrypted meta table), so `byn audit tail` and
`byn audit verify` work without unlocking.

---

## Per-vault files

Path: `~/.byn/vaults/<vault_name>/`. The default vault lives at
`~/.byn/vaults/default/`.

### `vault.db`

| | |
|---|---|
| Mode | `0600` |
| Format | SQLite (STRICT tables, WAL journal, FK enforced) |
| Created by | `internal/vault/store.go:Init` |

Tables: `meta`, `projects`, `envs`, `entries`, `entry_versions`,
`file_meta` (reserved). See
[architecture.md](architecture.md#sqlite-schema-v3-strict) for the
schema.

- **Names** (project, env, entry) are plaintext strings.
- **Values** are XChaCha20-Poly1305 AEAD ciphertext blobs:
  `nonce(24) || ct || tag(16)`. AAD = `vault_id ‖ 0x1F ‖ kind ‖ 0x1F ‖ name`.

The DB is **portable by design**: copy `vault.db + wrapped.key +
meta.json` and the same master password unlocks them on another machine.
The vault key is wrapped with `Argon2id(password)` **only** — no machine
binding — so forensics and recovery work on different hardware (owner
decision, 2026-06-11). The machine fingerprint touches only the trust
store's fp-MAC, never the vault key. The trade-off: the password wrap is
the at-rest security floor of the file, so a stolen copy is offline-crackable
down to your passphrase strength — pick a long, high-entropy one. (The
`wrapped_key_fingerprint` in `meta.json` is a SHA-256 of `wrapped.key` for
swap/tamper detection, **not** a hardware binding.)

### `vault.db-wal`, `vault.db-shm`

SQLite WAL mode artifacts. Transient — created during writes,
checkpointed and cleaned by SQLite. Don't back them up; back up
`vault.db` after a clean shutdown.

### `wrapped.key`

| | |
|---|---|
| Mode | `0600` |
| Format | Binary: `header || nonce || ct || tag` |
| Created by | `internal/vault/crypto/wrap.go:Wrap` |

Argon2id-wrapped vault key. Header carries:

- Version byte
- Argon2 time / memory / threads params + explicit salt/nonce length fields
- Salt (32 bytes)
- Nonce (24 bytes)

The AEAD AAD covers the *full header bytes*, so any byte tampered
in the header (including param changes for downgrade attempts) fails
to unwrap. See [security.md](security.md#2-key-wrapping-argon2id--aead)
for parameter values.

### `meta.json`

| | |
|---|---|
| Mode | `0600` |
| Format | JSON: `{"schema_version", "vault_id", "wrapped_key_fingerprint"}` |
| Created by | `internal/vault/meta.go:WriteMetaJSON` |

- `vault_id` — random UUID, used in row AAD.
- `wrapped_key_fingerprint` — SHA-256 of `wrapped.key`. Detects an
  attacker who swaps the wrapped key with a known one (e.g., from
  another vault they control).
- `schema_version` — current `3`.

The daemon checks the fingerprint against the actual file on every
open. Mismatch → vault refuses to open.

---

## Permissions reference

| Path | Mode | Reason |
|---|---|---|
| `~/.byn/` | `0700` | Created with strict default-deny |
| `daemon.sock` | `0600` | Plus peer-UID check at connect |
| `daemon.pid` | `0600` | Prevents another user from spoofing |
| `daemon.log` | `0600` | May contain stack traces; treat as sensitive |
| `auth-state.json` | `0600` | Includes timing info |
| `trusted_byn.json` | `0600` | Affects scope resolution |
| `audit/<vault>/*.log` | `0600` | Plain-text names; sensitive metadata |
| `vault.db` (+ WAL/SHM) | `0600` | Encrypted but mode still tightens |
| `wrapped.key` | `0600` | Useless without password, but still |
| `meta.json` | `0600` | Vault UUID + fingerprint |

The CLI never widens permissions. If `~/.byn` ever ends up
group-readable, run `chmod -R go-rwx ~/.byn` and audit how that
happened.

---

## Backup / restore

### Minimum backup

Per vault you want to preserve:

```
~/.byn/vaults/<vault>/vault.db
~/.byn/vaults/<vault>/wrapped.key
~/.byn/vaults/<vault>/meta.json
```

Plus, if you care about audit forensics:

```
~/.byn/audit/<vault>/*.log
```

### Restore

1. Stop the daemon: `byn daemon stop`.
2. Restore files preserving mode (`cp -p` or `rsync -a`).
3. Start the daemon: `byn daemon start`.
4. `byn unlock` with your password.
5. `byn doctor` to confirm schema + fingerprint + audit chain are
   all healthy.

### Caveats

- A restore on **another machine** works: the wrapped key is bound to your
  master password only, not to any hardware. The same password unlocks the
  restored vault anywhere. (The trust store and passkey enrollments do **not**
  carry across a machine boundary — see [Migration & setup](migration.md) for
  why `byn migrate --from` drops them and you must re-trust + re-enroll.)
- Don't restore stale `daemon.sock` / `daemon.pid` — let the daemon
  recreate them.
- `vault.db-wal` and `vault.db-shm` are transient. Don't restore.

---

## Related

- [Architecture](architecture.md) — schema details + per-vault state model.
- [Security model](security.md) — why each file is encrypted/signed/perm-protected.
- [CLI reference](cli-reference.md) — `daemon`, `doctor`, `audit`, `vault` commands.
