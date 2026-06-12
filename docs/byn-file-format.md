# `.byn` file format & discovery

How byn auto-detects the active scope from the current directory,
and how the TOFU trust model protects you from someone planting one.

---

## File format

`.byn` is a TOML file with a `[scope]` table, optional `[exec]` and
`[auth]` tables, and an optional `[aliases]` table.

```toml
[scope]
vault   = "default"
project = "myapp"
env     = "dev"

[exec]
env     = ["AWS_ACCESS_KEY_ID", "DATABASE_URL"]   # injection allowlist
actions = [
    "pytest {{args}}",                            # pattern: any pytest invocation
    "aws s3 cp {{path}} {{path}}",                # pattern: s3 copy with two paths
    "make build",                                  # exact match
]

[auth]
get = "none"   # optional: override the session gate per-op

[aliases]
deploy  = "kubectl apply -f deploy/"
test    = "cargo test"
migrate = "python manage.py migrate"
```

- `[scope]` fields are all optional. Omitted fields fall through to env
  vars and then daemon defaults.
- `[exec] env` is the **env-var injection allowlist** for `byn exec`:
  only the listed names are injected into the child. `"*"` (or `["*"]`)
  injects **all** scope vars — with a warning, since secrets added later
  are then auto-injected. An **empty or absent** `[exec] env` injects
  **nothing** (a project declares the vars it needs). With no `.byn` at
  all (ad-hoc run), `byn exec` injects the whole scope.
- **`[exec] actions`** is the **command allowlist**: controls which
  commands may run without per-call authorization. Three states:
  - *Absent or empty* (secure default) — every exec requires authorization.
  - Explicit list with optional typed placeholders — matching commands run
    freely; others require authorization. See [Actions pattern placeholders](#actions-pattern-placeholders) below.
  - `["*"]` — wildcard, all commands run freely (loud warning at
    `byn trust` time; avoid in production).
  Actions policy is read from the MAC-bound trust record (not the live
  file) — editing the `.byn` post-trust cannot change the effective
  policy without re-trusting.
- `[auth]` keys (`get`, `update`, `delete`, `exec`) override the session
  gate for this scope. Values: `"always"` (tightens, always requires fresh
  auth even with an active session), `"none"` (relaxes, skips the gate
  entirely), or absent (session gate decides). See [CLI reference](cli-reference.md)
  for the full policy semantics.
- **`[aliases]`** is a string-to-string map of named entry points for
  `byn exec NAME [ARGS...]`. See [`[aliases]` section](#aliases-section) below.
- Unknown keys are a **strict parse error** — typos and out-of-spec
  schemas don't silently turn into "default".
- An **empty** `.byn` file is a stop marker; see below.

> **Assisted authoring:** the portal `.byn studio` (open via `byn web`, then
> click the **.byn** button) is the recommended way to create and edit `.byn`
> files. It provides a structured builder form, an inline TOML validator, a
> command tester (simulate the exec gate before committing to trust), and
> one-click save+trust — all without hand-writing TOML. See
> [portal.md](portal.md) for the studio reference.

---

## Actions pattern placeholders

`[exec] actions` entries are patterns, not just exact strings. A pattern
is a whitespace-delimited sequence of tokens. Each token is either a
literal string or a **typed placeholder** that matches a class of values.

| Placeholder | Matches |
|-------------|---------|
| `{{uuid}}` | UUID (any case, with or without hyphens) |
| `{{int}}` | Integer (optional leading minus, then digits only) |
| `{{alnum}}` | Alphanumeric string (letters and digits) |
| `{{str}}` | Any single non-empty token (no whitespace) |
| `{{path}}` | Any single non-empty token without a NUL byte (syntactic only; no filesystem check) |
| `{{url}}` | An HTTP(S) URL |
| `{{re:...}}` | A custom regular expression (anchored to the full token) |
| `{{args}}` | Zero or more remaining tokens (**tail wildcard; must be last**) |

**Examples:**

```toml
actions = [
    "pytest {{args}}",            # pytest, pytest -v, pytest tests/foo.py, etc.
    "aws s3 cp {{path}} {{path}}", # exactly two path arguments
    "kubectl get {{alnum}}",       # kubectl get with any resource type
    "git commit -m {{str}}",       # single-token commit message
    "curl -o {{path}} {{url}}",    # download to a path
]
```

**Defense in depth:** patterns that fail to parse are **non-matching**
(they never widen the allowlist). Only malformed patterns are rejected at
`byn trust` time — the daemon validates `[exec] actions` before recording
the trust grant.

**Footgun:** a placeholder must occupy an **entire whitespace-delimited
token**. Partial-token placeholders like `--flag={{uuid}}` are rejected at
`byn trust` time with a clear error. Use a separate token form if your tool
supports it (`--flag {{uuid}}`), or pin the full flag literally.

---

## `[aliases]` section

The `[aliases]` table defines named entry points for `byn exec NAME [ARGS...]`.

```toml
[aliases]
deploy  = "kubectl apply -f deploy/"
test    = "cargo test"
migrate = "python manage.py migrate --noinput"
```

**Invocation:**

```sh
byn exec deploy                # expands to: kubectl apply -f deploy/
byn exec test -- --nocapture   # expands to: cargo test --nocapture
```

**Expansion rules:**

1. The daemon looks up `NAME` in the trust record's `[aliases]` map.
2. The alias value is split on whitespace to produce the base argv.
3. Any extra args you pass after the alias name are **appended**.
4. The expanded argv is then subject to the same `[exec] actions` pattern
   matching as a direct `byn exec -- COMMAND` call.

**`{{args}}` in alias values:** use `{{args}}` in the corresponding
`[exec] actions` pattern to allow variable extra args:

```toml
[exec]
actions = ["cargo test {{args}}"]   # matches "cargo test", "cargo test -v", etc.

[aliases]
test = "cargo test"
```

Then `byn exec test` → `cargo test` (no extra args, matches `{{args}}` at zero);
`byn exec test -- --nocapture` → `cargo test --nocapture` (matches `{{args}}`
with one token).

**Alias shadowing:** `byn exec test` (no `--`) runs the alias; `byn exec -- test`
runs the literal binary `test`. The `--` always forces direct form.

**Alias not found:** if the alias name is not defined in the trust record,
the daemon returns an error listing the available aliases (up to 8).

**Security contract:** aliases are stored in the MAC-bound trust record, not
read from the live `.byn` file at exec time. Editing the `.byn` after `byn trust`
cannot change the effective aliases without re-trusting (which requires the
password). An alias cannot reference another alias — only literal command strings.

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
- **mtime** — modification time at trust-grant time (v2 records). A
  `touch` that changes only the mtime is flagged as CHANGED, forcing
  re-trust; use `byn trust diff PATH` to confirm nothing changed.
- **snapshot** — full file body at grant time, used by `byn trust diff`.
- **MACs** — machine-fingerprint MAC + vault-key MAC (v2). Detects
  forged records and records copied from another machine.

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
| Trusted (path + hash match, mtime match, MACs valid) | **Inject** the allowlisted vars |
| Untrusted (no record) | **Abort** — `byn trust PATH` |
| Changed (hash or mtime differs) | **Abort** — re-approve with `byn trust PATH` (use `byn trust diff PATH` to see what changed) |
| Tampered (a MAC failed — forged / copied from another machine) | **Abort** — re-establish with `byn trust PATH` |
| Stale (record predates v2 hardening) | **Abort** — re-trust to add mtime + snapshot protection |

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
