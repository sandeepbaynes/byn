# `.byn` file format & discovery

How byn auto-detects the active scope from the current directory,
and how the TOFU trust model protects you from someone planting one.

---

## File format

`.byn` is a TOML file with a single `[scope]` table.

```toml
[scope]
vault   = "default"
project = "myapp"
env     = "dev"
```

- All three fields are optional. Omitted fields fall through to env
  vars and then daemon defaults.
- Unknown keys are a **strict parse error** — typos and out-of-spec
  schemas don't silently turn into "default".
- An **empty** `.byn` file is a stop marker; see below.

### Why TOML

Human-editable. Comment-friendly. Strict-mode parsing via
`github.com/pelletier/go-toml/v2` with `DisallowUnknownFields()`.

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

### Check on every CLI invocation

For every command that has a scope (i.e., not `trust`, `untrust`,
`daemon`, `doctor`, `help`, `version` — those skip discovery):

1. Walk for `.byn` (as above).
2. Read its contents, hash, canonicalize the path.
3. Look up the canonical path in `trusted_byn.json`.

Three outcomes:

| State | TTY mode | Agent mode (`--json`) |
|---|---|---|
| Path absent (first run) | `trust [y/N]:` prompt; `y` adds the record; `N` errors | **Hard fail** — `untrusted .byn (agent mode); run \`byn trust PATH\` from a terminal first` |
| Path present, hash matches | Apply the scope | Apply the scope |
| Path present, hash differs (tampered) | **Hard fail** — `untrusted .byn; run \`byn trust PATH\` to allow it` | **Hard fail**, same message |

### Why agent mode hard-fails

A CI job, an AI coding agent, or any non-interactive caller can't
meaningfully answer "trust this file?":

- Silent auto-trust → attacker who can plant `.byn` in a
  parent dir redirects every `byn exec` the agent does.
- Hanging prompt → the agent stalls.

Hard fail is the only safe choice. The human approves once in a
terminal; the agent uses it from then on.

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

- The `trusted_byn.json` file is protected only by UNIX perms
  (mode 0600 in `~`). An attacker who can write to it can pre-approve
  any `.byn`. Hardening (HMAC-sign the file with a daemon-resident
  key derived from machine fingerprint) is designed and deferred —
  see [security.md](security.md) and
  internal design notes.

- The discovery walk is CWD-relative. If you `cd` away mid-task and
  the parent dir's `.byn` is malicious, the next `byn` call
  would discover it. TOFU catches this (first-time → prompt), but
  it's a subtle interaction worth knowing.

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
