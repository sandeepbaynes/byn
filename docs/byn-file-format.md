# `.byn` file format & discovery

How byn auto-detects the active scope from the current directory,
and how the TOFU trust model protects you from someone planting one.

---

## File format

`.byn` is a TOML file with a `[scope]` table and an optional `[exec]` table.

```toml
[scope]
vault   = "default"
project = "myapp"
env     = "dev"

[exec]
env = ["AWS_ACCESS_KEY_ID", "DATABASE_URL"]   # injection allowlist for `byn exec`
```

- `[scope]` fields are all optional. Omitted fields fall through to env
  vars and then daemon defaults.
- `[exec] env` is the **injection allowlist** for `byn exec`: only the
  listed names are injected into the child. `"*"` (or `["*"]`) injects
  **all** scope vars — with a warning, since secrets added later are then
  auto-injected. An **empty or absent** `[exec] env` injects **nothing**
  (a project declares the vars it needs). With no `.byn` at all (ad-hoc
  run), `byn exec` injects the whole scope.
- `[exec] env` is **env-vars only** — it controls *which secrets are
  injected*, not *which command runs*. A trusted `.byn` runs any command
  you pass to `byn exec`; there is no command/script allowlist (yet).
- Unknown keys are a **strict parse error** — typos and out-of-spec
  schemas don't silently turn into "default".
- An **empty** `.byn` file is a stop marker; see below.

### Why TOML

Human-editable. Comment-friendly. Strict-mode parsing via
`github.com/pelletier/go-toml/v2` with `DisallowUnknownFields()`.

### Generating one from the portal

Hand-authoring is fine, but the web portal's **`.byn`** button writes one for
you: enter the project directory, multi-select which of the current scope's
env-vars go in the `[exec] env` allowlist, and optionally **trust now**
(password-gated) so `byn exec` works immediately. It writes `[scope]` for the
portal's active vault/project/env plus the chosen `[exec] env`.

---

## Discovery walk

Algorithm — `cmd/byn/discovery.go:discoverScope()`:

1. Start at the **current working directory** (`os.Getwd`).
2. Look for `<dir>/.byn`.
3. If it exists:
   - **Empty?** STOP — discovery returns no scope. Per-project escape
     hatch: drop an empty `.byn` in a subproject's root to shield
     it from a parent project's `.byn`.
   - **Non-empty?** Run the TOFU check (next section). On success,
     parse and return the scope.
4. If not found: walk to parent.
5. Stop conditions:
   - `dir == $HOME`
   - `dir == /` (filesystem root)
   - `dir == os.UserHomeDir()` (we never walk above your home)

A successful discovery emits a stderr hint:

```
Using scope from /Users/you/proj/.byn: default/proj/dev.
```

(suppressed when stderr isn't a TTY or `BYN_HINTS=0`)

---

## Trust-on-First-Use (TOFU)

Like SSH's `known_hosts`. We don't ship a list of "approved"
`.byn` files; we record what *you* approved, and detect changes
after.

### Storage

`~/.byn/trusted_byn.json`, mode 0600:

```json
{
  "records": [
    {
      "path":   "/Users/you/proj/.byn",
      "sha256": "2a9b0c6c646945c842f48c18c9735188f68088c3d5b51a6174dd2cc237c5ade7"
    }
  ]
}
```

- **path** — canonical absolute path, run through
  `filepath.EvalSymlinks`. (Needed because macOS makes `/tmp` a
  symlink to `/private/tmp`, so the same file appears under two
  paths.)
- **sha256** — SHA-256 of the file's bytes.

### Discovery applies the scope; `byn exec` enforces trust

**Discovery itself does not gate on trust.** It walks for `.byn`, parses
it, and applies the scope for *every* scoped command (`list`, `get`,
`put`, the TUI, …) — an untrusted `.byn` does **not** block them. A `.byn`
only redirects *which* secrets a command sees; the dangerous case is
injecting them into a child process.

**`byn exec` is the one command that verifies trust** — the verb that
injects secrets into a child. Before injecting, it asks the daemon to
MAC-verify the `.byn` (machine-fingerprint + vault-key MACs, see
[security.md](security.md)) and aborts on anything but `trusted`:

| State | What `byn exec` does |
|---|---|
| Trusted (path + hash match, MACs valid) | **Inject** the allowlisted vars |
| Untrusted (no record) | **Abort** — `byn trust PATH` |
| Changed (hash differs) | **Abort** — re-approve with `byn trust PATH` |
| Tampered (a MAC failed — forged / copied from another machine) | **Abort** — re-establish with `byn trust PATH` |
| Stale (record predates MAC hardening) | **Abort** — re-trust to add protection |

### Granting trust is a separate, password-gated act

Discovery never grants trust. You approve a `.byn` explicitly with
`byn trust PATH`, which **always requires the master password** — proof
that *you* are present, even when the vault is already unlocked. The
daemon owns the trust store and verifies the password (against the vault
the `.byn` targets, or `default`) before recording the approval.

This deliberately drops the old interactive `trust [y/N]` prompt. Two
reasons, both from the "owned by you, operated by many" threat model
(see [security.md](security.md)):

- A y/N prompt can be answered by the very agent that planted the file
  — it controls the CLI's stdin. A password it doesn't have cannot be.
- A previously-trusted `.byn` that *changed* would otherwise be silently
  re-trusted on a "y". Now a change is **refused** until a human
  re-approves it with the password.

So the human approves once, in a deliberate password-gated step; the
agent uses the result from then on but can never grant — or silently
re-grant — trust itself.

**Ceiling (be honest):** the password gate routes grants through the
daemon and closes the `byn trust` / prompt vectors, but a code-executing
same-UID process can still write `trusted_byn.json` directly — no
user-space gate stops that. Tamper-evidence for the store itself
(HMAC-signing) is a separate, planned hardening; see security.md.

---

## Skipping discovery

When you want to bypass the walk entirely:

- `byn --no-discovery ...` — one call.
- `BYN_NO_DISCOVERY=1 byn ...` — for a session/shell.

Discovery is also auto-skipped for these subcommands (they don't
operate on a vault scope, and skipping prevents an untrusted `.byn`
from locking you out of fixing it):

- `byn trust` / `byn untrust`
- `byn daemon ...`
- `byn doctor`
- `byn help` / `byn version`

---

## Examples

### Per-project pinning

```
~/projects/maison/
├── .byn             # [scope] project = "maison"
├── ...
└── src/
```

Inside `~/projects/maison/` and any subdir: `byn list` →
`maison/default`.

### Per-env pinning via env-var

`.byn` pins project; the engineer pins env per shell:

```sh
cd ~/projects/maison
export BYN_ENV=dev      # or staging, etc.
byn list                # maison/dev
```

### Shielding a subproject

Mono-repo with a different vault for one subproject:

```
~/work/
├── .byn              # [scope] project = "platform"
└── client-X/
    └── .byn          # [scope] vault = "client-X"  project = "auth"
```

Inside `~/work/client-X/`: scope = `client-X/auth/default`. The
parent `.byn` isn't consulted (the walk stops at the first hit).

### Per-project escape (empty file)

You want a subproject to use the daemon defaults, ignoring the
parent `.byn`:

```
~/work/
├── .byn              # [scope] project = "platform"
└── sandbox/
    └── .byn          # 0 bytes — STOP marker
```

Inside `~/work/sandbox/`: scope = `default/default/default`.

### Direnv combo

Keep secrets in byn; expose only the scope selection in the shell:

```sh
# .envrc
export BYN_PROJECT=maison
export BYN_ENV=dev
```

Now every `byn` invocation in the directory uses
`maison/dev` — no `.byn` file at all, no TOFU.

---

## Known weaknesses

- Granting trust is password-gated and daemon-owned, but the
  `trusted_byn.json` file itself is still protected only by UNIX perms
  (mode 0600 in `~`). A code-executing same-UID process can write it
  directly, bypassing the password gate. Tamper-evidence (HMAC-sign the
  file with a daemon-resident key) is designed and deferred to a
  separate slice — see [security.md](security.md).

- The discovery walk is CWD-relative. If you `cd` away mid-task and the
  parent dir's `.byn` is malicious, the next `byn` call would discover
  it — but a new or changed `.byn` is **refused** (run `byn trust` to
  approve), never auto-trusted, so it can't silently redirect you.

- No relative paths in `.byn`. There's no `path =` field; the
  file only carries scope (vault/project/env). Workspace-manifest
  features (per-command env allowlists, file-materialization) are
  a backlog item.

---

## Related

- [Security model](security.md) — TOFU rationale + agent mode + deferred hardening.
- [Architecture](architecture.md) — discovery in the request flow.
- [CLI reference](cli-reference.md) — `byn trust` / `byn untrust`.
- [File layout](file-layout.md) — where `trusted_byn.json` lives.
