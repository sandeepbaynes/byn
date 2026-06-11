# Portal — local browser admin UI

`byn web` opens the portal: a browser admin interface served by the daemon at
`http://localhost:2967` (port configurable via `[ui] port` in `~/.byn/config`).
All portal API calls go through the same daemon dispatch as the CLI — the same
vault-lock checks, ACLs, and audit log apply.

---

## Getting started

```sh
byn start          # daemon must be running
byn unlock         # vault must be unlocked
byn web            # opens the portal in your browser
```

The portal binds loopback only (`127.0.0.1`), never the network.

## The env-vars view

Values are masked by default. **Single-click** a value to reveal it (it re-masks
after `[ui] reveal_hide_after`, default 15s); double-click to edit. **Reveal all**
(toolbar) or **`Shift+R`** reveals/hides every value at once, authorizing once.
**import** / **export** read and write `.env` files.

For a non-default env (one that inherits `default`), **reset to default** removes
every override and added var in that env — leaving it inheriting `default`
entirely — after a confirm dialog. The `default` env and other envs are untouched.

## Trust boundary: loopback + owner-token

Binding to `127.0.0.1` blocks network access but does **not** prevent other
local user accounts from reaching the port over TCP — loopback has no kernel
UID gate on macOS or Linux. The Unix socket (`daemon.sock`, mode 0600) is
peer-UID-gated, but that gate does not extend to the HTTP port.

byn addresses this with an **owner-token gate** on every `/api/*` route, using
a two-token design that keeps the long-lived token out of `ps` output and URLs:

- On daemon start, a 32-byte random hex **persistent portal token** is written
  to `$BYN_DIR/portal.token` (mode 0600, created once and persisted across
  restarts). Only the owner UID can read it.
- Every `/api/*` request must carry an `X-Byn-Portal-Token` header equal to
  that value (constant-time compare). Missing or wrong → 401.
- `byn web` calls the UID-gated Unix socket to mint a **one-time bootstrap
  token** (60 s TTL, single-use, in-memory) and opens
  `http://localhost:<port>/?auth=<bootstrap-token>`. The persistent portal
  token never appears in argv or browser URLs.
- The SPA calls `POST /api/session/bootstrap` with the bootstrap token,
  receives the persistent portal token, stores it in `localStorage`, and strips
  `?auth=` from the URL via `replaceState`. A `ps`-captured bootstrap token is
  of limited value — it expires in 60 s and can only be used once.
- Subsequent page loads (reloads, tab reopens) use the `localStorage` copy.
  **Copyable URLs keep working** in an authorized browser.
- Static assets (`/static/`), the SPA fallback (`/`), and
  `POST /api/session/bootstrap` are **not gated by the owner-token** — the
  HTML is harmless, and the bootstrap endpoint uses the one-time token as its
  own credential. `POST /api/session/bootstrap` is still `sameOrigin`-gated so
  a cross-site page cannot replay a captured bootstrap token.

If the browser has no token in `localStorage` and an API call returns 401
`portal_token_required`, the SPA shows a full-screen notice:

> **This browser isn't authorized — run `byn web` from a terminal to open an
> authorized session.**

**CSRF defense (sameOrigin)** remains in place on all mutating routes: a
browser always sends `Origin` on a cross-site POST, so a malicious page cannot
drive the portal even if it obtains the token via XSS. The two layers are
complementary:

| Layer | What it stops |
|---|---|
| `requireToken` (owner-token) | Other-UID local processes reaching the loopback port |
| `sameOrigin` (Origin check) | Browser CSRF from a different origin |

---

## What requires authentication

There is no portal login. Like `byn ls`, the scope tree and entry **names**
are always visible. The following operations require the vault to be unlocked
(or the master password / passkey presence token on the relevant request):

| Operation | Auth required |
|---|---|
| Reveal an entry value | vault unlocked (or per_action_auth password/token) |
| Write/delete/rename entries | vault unlocked (or per_action_auth password/token) |
| Write/delete/rename scopes | vault unlocked |
| Trust a `.byn` file | master password or passkey token |
| Edit global config | master password or passkey token (always) |

When `[security] per_action_auth` is on, reveal/write/delete actions trigger
an in-page "Authorize" step-up: passkey (Touch ID) first, then password
fallback. On success the daemon issues a single-use presence token consumed
by the retry.

Disable the portal entirely with `[ui] enabled = false` in `~/.byn/config`.

---

## .byn studio

The `.byn studio` (accessible from the top-left **.byn** button) is an
assisted authoring environment for `.byn` project scope files. Use it to
build, validate, simulate, and save `.byn` files without touching TOML by hand.

### Builder mode

The **builder** tab presents a structured form:

- **Project directory** — the target directory where `Dir/.byn` will be
  written. Use the `browse…` button or type a path directly.
- **Vault / project / env scope** — drop-downs (populated from the live daemon)
  that fill the `[scope]` table.
- **Env-vars to inject** — a checkbox list of every entry in the selected
  scope; tick the ones `byn exec` should inject into the child process. An
  **inject ALL vars ("\*")** toggle injects every secret instead of a list.
  **Reveal all** (top-right of the card, or press **`Shift+R`** — same key as
  the TUI) shows the real value next to every scope var so you don't have to switch
  to the env view. You can also **single-click any one value** to reveal/hide
  just that var; **double-click a value** toggles its inject switch (clicking the
  name or switch toggles it too). Reveal goes through the audited reveal path:
  the vault must be unlocked, and with `per_action_auth` on it prompts for your
  password or passkey first (reveal-all authorizes once). Values re-mask after
  `[ui] reveal_hide_after` (default 15s) and when you leave the studio.
- **Actions allowlist** — commands that may run without per-call auth. An
  **allow ALL commands ("\*")** toggle mirrors the env wildcard toggle.

Switch to **raw** mode at any time to hand-edit the generated TOML directly.
Builder and raw stay in sync: switching back re-parses the raw TOML and
reflects the values in the form. **Reset** (top-right) restores the editor to
the loaded file — or blank defaults — and is available in both modes.

A **pretty format** checkbox below the raw editor (shown in raw mode only)
chooses how arrays are laid out in the generated `.byn`: unchecked
(**minified**) keeps each array on one line (`env = ["A", "B"]`), checked
(**pretty**) puts one element per line. `[exec] env` and `actions` are formatted
identically either way. The choice persists in the browser (like the theme
switcher) and also governs files saved from builder mode. Toggling it reformats
the textarea by re-parsing the TOML; invalid or unparseable content is left
exactly as typed.

### Validator (inline)

Every keystroke in raw mode (and every form change in builder mode) sends the
current content to `POST /api/byn/validate`. Errors and warnings appear below
the editor in real time:

- **Errors** (red) — must be fixed before the file can be saved:
  - TOML parse errors
  - Invalid `[auth]` values
  - Invalid `[exec] actions` patterns
- **Warnings** (amber) — advisory:
  - `env = "*"` injects all scope vars (consider an explicit list)
  - `actions = "*"` allows every command re-auth-free
  - No actions declared (every exec will require authorization)
  - `[auth] exec = "none"` is wildcard-equivalent
  - Actions ending in `{{args}}` (any extra args accepted)
  - Shell-interpreter actions with placeholders (injected env visible to scripts)

### Command tester (simulate)

The **test a command** section predicts the exec gate verdict without running
anything. Type a command line and press **test** to call
`POST /api/byn/simulate`. The result shows:

- **Verdict**: `free` (runs without extra auth) or `auth` (requires authorization)
- **Matched by**: which action pattern or policy (`[auth] exec`, wildcard, or none)
- **Resolved argv**: the final argument list after alias expansion

The simulator uses the same gate matrix as `handleExecFetch` (the real
enforcement path) and is cross-checked by unit tests that run both on the same
content — the simulator cannot drift from enforcement.

### Open existing

The **open .byn…** button lets you load a file already on disk:

1. The panel first lists trusted `.byn` files (from `byn trust list`). Click
   one to load it directly.
2. Choose **browse filesystem…** to navigate with the directory picker, then
   click a directory — the studio loads `<dir>/.byn`.

The file is fetched via `POST /api/byn/read` (sameOrigin-protected). The trust
chip in the top-left shows the current trust status (`trusted`, `untrusted`, or
`changed`).

### Save

Click **save .byn** to write the current content to `<project-dir>/.byn`. A
checkbox lets you trust it in the same step (requires master password or
passkey). The response shows the effective policy (actions, auth overrides,
aliases) so you can review it before relying on it.

---

## Settings panel

The **Settings** panel (gear icon, top-right) exposes the global config file
(`~/.byn/config`) as a TOML editor.

- **Read**: the current config is loaded via `GET /api/config` (no auth
  required — the config contains no secrets).
- **Write**: click **save config** to validate and atomically write the new
  content, then live-reload the daemon. This always requires the master
  password or a passkey presence token — even if `per_action_auth` is off —
  because config controls the daemon's own security settings (e.g. turning
  `per_action_auth` on or off).

The editor shows a live diff of what will change on reload. If the TOML is
invalid the daemon rejects the write before touching disk; the existing config
is never modified.

Notable settings visible in the panel:

| Key | Default | Effect |
|---|---|---|
| `[ui] port` | `2967` | Portal listen port |
| `[ui] enabled` | `true` | Disable the portal |
| `[ui] reveal_hide_after` | `"15s"` | Re-mask revealed values after this long; `"0s"` = never |
| `[security] per_action_auth` | `false` | Require step-up auth for every value read/write |
| `[daemon] idle_timeout` | `"15m0s"` | Auto-lock all vaults after inactivity; `"0s"` disables |

Durations use Go syntax (`"15s"`, `"1m30s"`, `"0s"`).

---

## API surface (summary)

All portal API calls proxy to in-process daemon dispatch. The studio-specific
routes:

| Method | Route | Auth | Description |
|---|---|---|---|
| `POST` | `/api/byn/validate` | none | Validate `.byn` content (errors + warnings) |
| `POST` | `/api/byn/simulate` | none | Simulate exec verdict for a command line |
| `POST` | `/api/byn/read` | none (sameOrigin) | Read a `.byn` file with trust status |
| `POST` | `/api/byn/write` | password/token if trust=true | Write `.byn`; optionally trust |
| `GET`  | `/api/config` | none | Read global config TOML |
| `POST` | `/api/config` | always (password/token) | Validate + write + reload config |
| `GET`  | `/api/fs/listdir?path=` | none (sameOrigin) | List subdirectories for the dir picker |

`POST /api/byn/read` uses POST (not GET) with an sameOrigin check so
cross-origin pages cannot use it as an arbitrary file-read oracle. The daemon
additionally enforces that the **resolved** (symlink-dereferenced) basename of
the path is exactly `.byn` — a symlink named `.byn` pointing at another file
is refused.

---

## Related

- [`byn-file-format.md`](byn-file-format.md) — `.byn` TOML schema, actions
  patterns, and the TOFU trust model.
- [`cli-reference.md`](cli-reference.md) — `byn trust`, `byn exec`, `byn web`.
- [`security.md`](security.md) — portal CSRF posture, loopback-only binding.
