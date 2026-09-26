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

---

## The env-vars view

Values are masked by default. **Single-click** a value to reveal it (it re-masks
after `[ui] reveal_hide_after`, default 15s); double-click to edit. **Reveal all**
(toolbar) or **`Shift+R`** reveals/hides every value at once, authorizing once.
**import** / **export** read and write `.env` files, carrying each value's
description and notes as the comment block above it: `#` lines for the
description, one `##` line per note. This is the same format `byn import` and
`byn export` use (see the [CLI reference](cli-reference.md)). An export
includes your notes in plaintext, so treat the file like any `.env`.

For a non-default env (one that inherits `default`), **reset to default** removes
every override and added var in that env — leaving it inheriting `default`
entirely — after a confirm dialog. The `default` env and other envs are untouched.

Per-row, a non-default env adds two actions:

- **revert** (on an *overridden* var — one that also exists in `default`) drops
  this env's override so the row falls back to the `default` value. While the
  vault is unlocked it is instant with an **undo** toast; while locked it asks
  for the master password first (no undo, since the value can't be read back).
- **persist** (on an *overridden* or *new* var) promotes this env's value into
  `default` and removes the local copy, so this env — and every env inheriting
  `default` — resolves to it. It requires the vault unlocked (writing to
  `default` must encrypt) and confirms first, because it changes the shared
  `default` (replacing its existing value for an override).

---

## Trust boundary: loopback + owner-token

Binding to `127.0.0.1` blocks network access but does **not** prevent other
local user accounts from reaching the port over TCP — loopback has no kernel
UID gate on macOS or Linux. The Unix socket (`daemon.sock`, mode 0600) is
peer-UID-gated, but that gate does not extend to the HTTP port.

byn addresses this with an **owner-token gate** on every `/api/*` route, using
a two-token design that keeps the long-lived token out of `ps` output and URLs:

- On daemon start, a 32-byte random hex **persistent portal token** is written
  to `portal.token` in the byn data dir (mode 0600, created once and persisted
  across restarts). Only the owner UID can read it.
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
| Reveal an entry value | vault unlocked (session or password/token required) |
| Write/delete/rename entries | vault unlocked (session or password/token required) |
| Write/delete/rename scopes | vault unlocked |
| Trust a `.byn` file | master password or passkey token |
| Edit global config | master password or passkey token (always) |

Reveal/write/delete actions trigger an in-page "Authorize" step-up when no
session is active: passkey (Touch ID) first, then password fallback. On success
the daemon issues a single-use presence token consumed by the retry.

Disable the portal entirely with `[ui] enabled = false` in `~/.byn/config`.

---

## Portal sessions (NU-3)

When `byn unlock` succeeds through the portal, the daemon mints a per-vault
session stored in **daemon-process memory** (not on disk — there is no
controlling TTY for the browser context). Portal sessions are bound to the
vault name and the daemon owner's UID; they are not TTY-scoped. A browser page
reload keeps the session active (the persistent portal token in `localStorage`
re-authenticates the request, and the in-memory session is still live). `byn
lock` clears all sessions for that vault. The daemon auto-expires portal sessions
on the same TTL and idle timers as CLI sessions (`[security] session_ttl`,
default 12 h; `[security] session_idle`, default 0 — inherit `idle_timeout`).

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
  the vault must be unlocked and it prompts for your password or passkey when
  no session is active (reveal-all authorizes once). Values re-mask after
  `[ui] reveal_hide_after` (default 15s) and when you leave the studio.
- **Actions allowlist** — commands that may run without per-call auth. An
  **allow ALL commands ("\*")** toggle mirrors the env wildcard toggle.
- **Writable dirs** — extra tool-state directories the privilege-separated exec
  child (`_byn-exec`, a different UID) may read/write — e.g. a package manager's
  global store under a `0700` home — written to `[exec] writable`. Granted at
  `byn trust` time on top of a curated default set; each path must resolve under
  your home. Most stacks need none.
- **Aliases** — named entry points written to `[aliases]`; `byn exec <name>`
  expands to the mapped command.
- **Auth overrides** — per-operation auth policy (`[auth]` for get/update/delete/exec):
  `default`, `always` (force fresh auth every call), or `none` (disable the gate —
  use sparingly).

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

## Approvals

The decision queue, at `/approvals` — reachable from the nav badge, which counts
what is waiting.

Each card leads with the request id (the thing you type at a terminal, and the
`approval_id` an agent printed), then what would run, whether the asker asked for
a **single use**, the stated reason marked as unverifiable, and who asked as read
from the kernel.

- **approve** hands out authority, so it asks for the master password exactly as
  the terminal does. The primary button does what the asker asked for — a
  one-shot request is approved as a one-shot by the plain button, so the narrow
  path is the default path — and the override sits beside it labelled with what
  it does rather than with a flag name.
- **deny** asks for no password. Refusing grants nothing, and it has to stay the
  cheaper action or people learn to approve by reflex.
- Both dialogs take an optional **reason**, carried back to whoever asked through
  their watch. On a refusal it is the difference between an agent that fixes its
  request and one that asks the same thing again.
- **history** shows decided and expired requests with their outcomes and reasons.
- **revoke** appears where there is a live grant to take back. It is named apart
  from deny because the two are easily confused, and denying something already
  approved does *not* remove the grant.

The rules — what `once` and `always` mean together, whether a password is
required — live in the daemon. The portal carries the fields and does not decide,
so a tap here and `byn approve <id>` cannot drift apart.

## Settings panel

The **Settings** panel (gear icon, top-right) exposes the global config file
(`~/.byn/config`) as a TOML editor.

- **Read**: the current config is loaded via `GET /api/config` (no auth
  required — the config contains no secrets).
- **Write**: click **save config** to validate and atomically write the new
  content, then live-reload the daemon. This always requires the master
  password or a passkey presence token because config controls the daemon's
  own security settings.

The editor shows a live diff of what will change on reload. If the TOML is
invalid the daemon rejects the write before touching disk; the existing config
is never modified.

Notable settings visible in the panel:

| Key | Default | Effect |
|---|---|---|
| `[ui] port` | `2967` | Portal listen port |
| `[ui] enabled` | `true` | Disable the portal |
| `[ui] reveal_hide_after` | `"15s"` | Re-mask revealed values after this long; `"0s"` = never |
| `[daemon] idle_timeout` | `"15m0s"` | Auto-lock all vaults after inactivity; `"0s"` disables |
| `[security] session_ttl` | `"12h0m0s"` | Absolute session lifetime; `"0s"` = no absolute cap (needs daemon restart) |
| `[security] session_idle` | `"0s"` | Sliding session idle window; `"0s"` = inherit `[daemon] idle_timeout` (needs daemon restart) |
| `[security] privsep` | _absent (off)_ | Run trusted-`.byn` exec children as `_byn-exec` — requires `sudo byn setup` provisioning + a daemon restart |
| `[annotations] max_description` | `4096` | Largest description, in bytes. A description is **plaintext** and readable without a credential — this is the size of what anything reading the vault can be handed |
| `[annotations] max_note` | `65536` | Largest single note, in bytes (notes are encrypted) |
| `[annotations] max_notes_per_object` | `200` | How many notes one object may carry |

The **Settings** view renders every key above as a form field (with a raw-TOML
mode). Durations use Go syntax (`"15s"`, `"1m30s"`, `"0s"`).

---

## Descriptions and notes

Every entry row carries a **describe · notes** action, and its description has
its own column after the value. Long descriptions are clipped to two lines;
hover for the whole text, or double-click the cell to edit it in place (Enter
saves, Esc cancels). Editing a value, or adding a new one, shows a description
box beside it, and the description is saved with the value if you changed it. Drag the right
edge of the **KEY** or **VALUE** header to resize those columns (the description
takes the rest); the widths are remembered in this browser, and double-clicking
a header edge resets it.

- A **description** is plaintext and is readable while the vault is locked, by
  anything that can reach byn — including an agent with no credential. The
  editor says so. **Do not put a secret in one.**
- **Notes** are encrypted. The panel lists them with their author and time and
  takes a new one; with the vault locked it shows the count and says that
  reading them needs an unlock, rather than showing an empty list. Each note
  can be **edited** in place (⌘/Ctrl+Enter saves, Esc cancels) or **removed**
  (confirmed in the row). Its **history** icon lists every version: what it
  said, whether it was added, edited or removed, who did it (you, or the
  agent and its process name) and when. Removal is a tombstone, so **show
  removed notes** lists removed notes with their history; they are gone for
  good only when the variable is deleted. Every add, edit, removal and
  history read is also in the audit log.

Text you did not write is badged: `.byn` for a description a trusted manifest
declares, and `agent: <name>` for one a process wrote when it created the value.
Removing a note asks first and says what removal means — the note leaves the
list and its text stays in the annotation history.

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
| `GET`  | `/api/annotations?type=&name=&id=&kind=` | none | Read annotations. Descriptions come back for any caller; notes need the session, and are reported as withheld rather than absent when they exist |
| `POST` | `/api/annotation/describe` | password/token when no session | Set or clear a description |
| `POST` | `/api/annotation/note` | password/token when no session | Add, edit (`id`) or remove (`id` + `remove`) a note |
| `POST` | `/api/annotation/history` | password/token when no session | Every version of one annotation |

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
