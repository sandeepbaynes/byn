# TUI design (Slice 7)

The authoritative spec for the bubbletea+lipgloss TUI. Built once
from this doc; updated when the doc changes.

Read this with [architecture.md](architecture.md) (data model + IPC),
[security.md](security.md) (reveal semantics), and
[cli-reference.md](cli-reference.md) (equivalent CLI commands).

---

## Goals

1. **Replace** the 1600-line raw-byte `cmd_tui.go` with a responsive,
   modal, vi-style TUI.
2. **Multi-scope navigation** — left-rail tree over `vault → project →
   env`. The whole tree on disk is reachable without leaving the TUI.
3. **Responsive layout** — works correctly from 40×12 up to "huge"
   without manual tweaking. Resize is observed (SIGWINCH) and
   re-renders cleanly with no flicker.
4. **Parity with the future browser UI** — same logical regions, same
   data model, same vocabulary, so the Phase 2 web UI has minimal
   design overhead.
5. **Modal vi-style keymap** — NORMAL / INSERT / VISUAL / COMMAND /
   SEARCH / SCOPE / AUDIT / HELP / CONFIRM. Anyone who's used vim or
   neovim is at home.

Non-goals (explicit deferrals):
- File-content entries (Phase 5). The Files section is shown empty.
- Versioning / history beyond Large-tier detail-pane preview (entry
  history IPC ops not yet shipped — see Slice 5 deferrals).
- Mouse support. Possible but out of scope; vi-style keys only.

---

## Layout tiers

Five tiers driven by `(width, height)`. Computed by
`internal/tui/layout.Compute(w, h) Layout`.

| Tier | Width | Rail | Detail pane | Audit inline | Date format |
|---|---|---|---|---|---|
| **Below-min** | < 40 OR rows < 12 | — | — | — | — |
| **Tiny** | 40-59 | breadcrumb only | no | no | `MM-DD` |
| **Medium** | 60-89 | yes, 20 cols | no | yes (last 2) | `MM-DD` |
| **Standard** | 90-119 | yes, 26 cols | no | yes (last 3) | `YYYY-MM-DD` |
| **Large** | 120+ | yes, 26 cols | yes, 32 cols | yes (last 3) | `YYYY-MM-DD` |

Rail widths were bumped 2026-06-02 (Medium 14→20, Standard/Large 17→26)
so common names like `default`, `staging`, `platform`, `myapp-prod`
fit at depth 2 without ellipsis. 1-column gutter between adjacent
visible panes; total fits within `width`.

Vertical responsiveness inside each tier:

| Rows | Behavior |
|---|---|
| < 12 | Below-min screen |
| 12-19 | Drop RECENT AUDIT; drop FILES if empty |
| 20-29 | Standard heights (rail scrolls, content sections trim to visible) |
| 30+ | Roomy spacing; more audit rows |

`Layout` shape:

```go
type Layout struct {
    Tier       Tier   // BelowMin | Tiny | Medium | Standard | Large
    Width      int
    Height     int
    Rail       Rect   // x=0,y=1,w=tierRail,h=Height-2  (or zero Rect on Tiny)
    Content    Rect
    Detail     Rect   // zero Rect when not visible
    Status     Rect   // x=0, y=Height-1, w=Width, h=1
    DateFmt    string
    AuditRows  int    // 0 when hidden
    ShowFiles  bool   // false when room is tight and files=0
}
```

Status line is constant: 1 row at bottom, full width. `Rect{}` means
"hidden".

---

## Pane architecture

### Top bar (1 row, in Content area)

- Standard/Large: `default / billing / staging                  unlocked`
- Tiny: replaces full top bar — `default ▸ billing ▸ staging   unlocked`

### Rail (left sidebar)

- Vault tree, collapsible nodes.
- Markers: `▼` open, `▶` closed, `●` selected leaf, `○` unselected leaf.
- `[+ new vault]` row pinned at the bottom of the rail.
- Long names truncated with `…`.
- Scrolls when the tree exceeds visible rows.
- Hidden on Tiny (breadcrumb in top bar conveys the same info).

### Content (main pane)

Three stacked sections, each with a section header:

1. **ENV-VARS** — list of entries in `(scope.Project, scope.Env)`.
   - Each row: `name`, masked-value bar (▼=dots, length proportional
     to byte size capped at 16 chars), `size`, `last-updated date`.
   - Selected row prefixed `▸`.
   - `+ add (a)` action hint on the header row.
2. **FILES** — placeholder for Phase 5. Always shows `(none — Phase 5)`.
   - Hidden entirely when the layout is tight (Tier vertical).
3. **RECENT AUDIT** — last N events for the active vault.
   - Format: `HH:MM  op  entry  outcome`.
   - `view all (ga)` hint on the header.
   - Hidden on Tiny.

### Detail (right sidebar, Large only)

When `Layout.Detail` is non-zero, the focused entry's detail shows:

- Title: entry name + state (e.g. `STRIPE_SK (editing)`, `(revealed 7s)`).
- Metadata: Created / Updated / Size / Source.
- Mode-specific block: `UNSAVED CHANGES` when INSERT, `AUDIT EVENT
  EMITTED` when REVEAL, `HISTORY` always (3 most recent revisions —
  pending revision shown as `◆ pending` during INSERT).
- Action hints: `R reveal  y copy  e edit`.

### Status line (1 row, bottom)

Always rendered. Format:
`MODE  context-chip(s)  hotkey-hints`

`MODE` is colored: NORMAL=dim, INSERT=cyan, VISUAL=yellow,
COMMAND=blue, SEARCH=magenta, REVEALED=red-bold,
AUDIT/HELP/SCOPE=cyan, CONFIRM=red.

In COMMAND/SEARCH mode the status line becomes the input field:
`: env stag█` / `/ STRIPE█`.

---

## Modes

```
NORMAL ── i ──> INSERT ── ESC ──> NORMAL
       ── a ──> ADD-ENTRY ── :w / ESC ──> NORMAL
       ── R ──> REVEAL (7s) ── ESC / R / timeout ──> NORMAL
       ── dd ──> CONFIRM-DELETE ── d / ESC ──> NORMAL
       ── s ──> SCOPE-PICKER ── Enter / ESC ──> NORMAL
       ── : ──> COMMAND ── Enter / ESC ──> NORMAL
       ── / ──> SEARCH ── Enter / ESC ──> NORMAL
       ── ga ──> AUDIT-VIEW ── q ──> NORMAL
       ── ? ──> HELP ── ESC ──> NORMAL
       ── v ──> VISUAL ── ESC ──> NORMAL (Phase B; deferred from MVP)
```

### NORMAL (default)

Read-only navigation. Focus is one of two panes: `Rail` or `Content`.
`Tab` swaps focus.

Keys (in focused pane):

| Key | Action |
|---|---|
| `j` / `k` | Move cursor down/up |
| `h` / `l` | (Rail) fold/unfold node or exit/enter content. (Content) sometimes deselects/selects detail pane. |
| `g` / `G` | First / last row |
| `Tab` | Swap focus rail ↔ content |
| `Enter` | (Rail) activate leaf (jump to that scope). (Content) view selected entry's metadata in popover (or detail pane on Large) |
| `i` | Edit selected entry (→ INSERT) |
| `a` | Add new entry (→ ADD-ENTRY); on rail, add at the focused level (`+ new vault` etc.) |
| `r` | Rename selected entry (→ INSERT for the name field only) |
| `dd` | Delete selected entry (→ CONFIRM-DELETE) |
| `R` | Reveal selected value (→ REVEAL) |
| `y` | Copy selected value to clipboard (audited) |
| `s` | Scope picker (→ SCOPE-PICKER) |
| `:` | Command palette (→ COMMAND) |
| `/` | Search/filter (→ SEARCH) |
| `?` | Help (→ HELP) |
| `q` / `:q` | Quit |
| `gd` | Toggle detail pane (Large only; otherwise no-op) |
| `ga` | Audit view (→ AUDIT-VIEW) |
| `Ctrl-l` | Force re-render |

### INSERT

Editing an entry's value. The selected row expands inline; an
editable text box appears with cursor.

Keys:

| Key | Action |
|---|---|
| Typing | Inserts into the value buffer |
| `Backspace`, arrow keys, Home/End | Standard text editing |
| `ESC` | Switch to NORMAL (changes kept in buffer; not committed) |
| `:w` | Commit (OpPut), back to NORMAL |
| `:q` | Cancel, discard buffer, back to NORMAL |
| `:q!` | Force-cancel even if unsaved |
| `:wq` | Save and quit edit |

Status line: `INSERT  STRIPE_SK    ESC normal   :w save   :q cancel   28/4096 B`.

The `n/MAX B` counter shows current size against the 4096-byte env-var
soft limit. (Soft = above this we warn but still save; hard size is
the SQLite blob ceiling.)

### REVEAL

Decrypts the value, displays it inline for 7 seconds, audits the read.

| Key | Action |
|---|---|
| `R` | Extend timer by another 7s (audited; another `get` event) |
| `y` | Copy to clipboard (audited) |
| `e` | Switch directly to INSERT mode |
| `ESC` | Hide immediately |
| Timeout | Auto-hide |

Status line: `NORMAL  STRIPE_SK  REVEALED   ESC hide  y copy  e edit`.
The MODE label flips to `REVEALED` (red-bold) for the entire reveal
window.

### ADD-ENTRY

A two-field form (NAME + VALUE) shown inline at the position where
`a` was pressed.

- `Tab` cycles NAME → VALUE → NAME.
- Name validation: identifier-style (`[A-Z][A-Z0-9_]*` warning if
  not, but accept anything; identifier-like names are recommended).
- Duplicate-name check on commit (`OpPut` with `--create-only`).
- `:w` saves, `:q` cancels.

Status line: `INSERT  (new entry)        Tab field   :w save   :q cancel`.

### SCOPE-PICKER (`s`)

Centered modal with 3 columns (vault | project | env). Active column
highlighted; arrow keys / `j` / `k` navigate within; `Tab` next
column; `Enter` applies; `ESC` cancels.

On Large, the modal widens to show entry-count and last-active
metadata per row.

### COMMAND (`:`)

Status line becomes a single-line input. Tab completes against the
command catalog (`help_text.go` `commandHelp` keys plus mode-specific
ones).

Supported commands:

| Cmd | Effect |
|---|---|
| `:w` | Save current edit |
| `:q` | Quit current mode (or app from NORMAL) |
| `:q!` | Force quit |
| `:wq` | Save + quit |
| `:env NAME` | Switch active env |
| `:project NAME` | Switch active project |
| `:vault NAME` | Switch active vault |
| `:put NAME` | Open ADD-ENTRY with NAME pre-filled |
| `:get NAME` | Reveal NAME |
| `:delete NAME` | Delete NAME (with confirm) |
| `:audit` | Open AUDIT view |
| `:doctor` | Run doctor; show results in a modal |
| `:lock` | Lock current vault |
| `:export ...` | Run an export, write to a file the user names |
| `:reload` | Refresh data from daemon |
| `:help X` | Open HELP at section X |

### SEARCH (`/`)

Status line input. As you type, the content pane filters entries in
the current scope (case-insensitive substring on name).

`Enter` commits (filter persists), `ESC` clears + reverts.

### AUDIT-VIEW (`ga`)

Replaces the Content pane with a sortable audit log table.

- `j`/`k` scroll rows.
- `/` filters.
- `v` runs `OpAuditVerify` and shows the result inline.
- `r` refreshes.
- `q` returns to NORMAL.
- On Large, the Detail pane shows the highlighted event's full record.
- Default ordering: newest first.

Columns: `WHEN  OP  ENTRY  OUTCOME` (size-adapted to tier).

### HELP (`?`)

Full-screen modal listing all keybindings grouped by section
(Navigation, Editing, Scope, Other). `ESC` closes. `/` filters.

### CONFIRM-DELETE (`dd`)

Centered modal. The selected entry name appears in the title. Press
`d` again to confirm, `ESC` to cancel. Two-key gesture matches vim
`dd`.

## Draft / save semantics (vi-style; no auto-save)

Added 2026-06-02 in response to "all values get saved by default as
soon as I edit" feedback.

- Typing in INSERT / ADD / RENAME mutates a local `editBuf` only —
  the daemon is not contacted.
- `editBuf.Dirty()` reports whether the buffer differs from its
  original state (INSERT compares `Value vs OriginalVal`; ADD treats
  any non-empty name/value as dirty; RENAME compares the new name).
- `:w` (or `:wq`) commits via a single `OpPut`. On success, the
  draft is cleared and mode returns to NORMAL.
- `:q` from edit context refuses if dirty (`unsaved edit — :w to
  save or :q! to discard`).
- `:q!` discards unconditionally.
- `:wq` is `:w + return to NORMAL`. It does NOT quit the whole TUI.
- `ESC` from INSERT/ADD/RENAME drops to NORMAL but **preserves**
  the draft. Status line flashes the recovery hint.
- `q` from NORMAL: quits the TUI only if no dirty draft exists.
  Same guard as `:q`.

Indicators (so a draft cannot be silently lost):
- Status line shows a red `[DRAFT: NAME]` (or `[DRAFT: (new)]`) chip
  whenever a dirty draft exists in NORMAL mode.
- The dirty entry's row in NORMAL view shows a red `[*]` prefix.
- Flash messages on every guard rail (`q`, `:q`, attempting to
  start a different edit).

Concurrent-edit safety:
- Pressing `i` on the same entry that has an open draft RESUMES the
  draft (no daemon re-fetch).
- Pressing `i` / `a` / `r` while a dirty draft exists for a
  DIFFERENT entry refuses with `unsaved draft on "X" — :w or :q!
  first`.

Enter key behavior (corrects an earlier auto-commit bug):
- INSERT existing value → inserts literal `\n`. Multiline values
  (PEM keys, etc.) work.
- ADD NAME field → advances to VALUE field (names are single-line
  identifiers).
- ADD VALUE field → inserts `\n`.
- RENAME → ignored (names are single-line).
- Enter NEVER commits. `:w` is the only commit path.

## Undo / redo / clipboard

Added 2026-06-02. All three operate on the draft buffer; none touch
the daemon directly (except `y` which fires an audited `OpGet`).

### Undo / redo

- `u` (NORMAL): undo last change in the draft buffer.
- `Ctrl+R` (NORMAL): redo.
- Snapshot taken **before every mutation** (rune insert, backspace,
  Enter-as-newline, paste). One step per keystroke.
- History capped at **200 snapshots** per draft; oldest dropped first.
- Standard redo behavior: typing fresh after an undo trims the redo
  tail.
- Works across the ESC boundary — type, ESC to NORMAL, `u` rolls
  back, `i` to resume the rolled-back version.

### Clipboard

- `y` (NORMAL, entry selected): fires `OpGet` for the selected
  entry, writes the value to the system clipboard via
  `github.com/atotto/clipboard`. Audit event recorded — same
  forensic surface as `R` reveal.
- `y` (REVEAL): copies the already-revealed value. No extra IPC
  roundtrip.
- `p` (NORMAL): pastes clipboard into the currently-open draft at
  cursor. Refuses if no draft is open.
- `Ctrl+V` (INSERT value field): pastes inline while typing.
- `clipboardWrite` is a package-level var so tests stub it (CI
  runners have no clipboard).

## Inheritance badges (non-default envs)

Added 2026-06-02. When the active env is not `default`, every entry
row shows a 1-cell badge column:

| Badge | Meaning | Style |
|---|---|---|
| `↓` | inherited from default env (Source=default) | dim cyan |
| `⤴` | exists in both; this env overrides default | bold yellow |
| `✦` | created in this env only | bold green |

Implementation:
- When the scope changes to a non-default env, a second `OpList` is
  fired with `Env: "default"` to fetch the default env's entry
  names. Cached in `m.defaultEnvNames` for the lifetime of the scope.
- `entryStatus(e)` classifies each row:
  - `e.Source == "default"` → `StatusInherited`
  - `e.Source == "scope"` AND `e.Name in defaultEnvNames` →
    `StatusOverridden`
  - `e.Source == "scope"` AND name NOT in default's list →
    `StatusNew`
- A one-line legend renders under the ENV-VARS header whenever
  badges are showing.
- When active env IS `default`, the badge column is hidden entirely
  (nothing to compare against).

## Scope picker cascade

Added 2026-06-02. The 3-column scope-picker modal (`s`) now keeps
the env column populated as the vault cursor moves:

- Moving the vault cursor in column 0 cascades: projects update,
  and envs ALSO update using either the matching project (if a
  project of the user's current `m.scope.Project` exists in the new
  vault) or `projects[0]`.
- Same for env: tries to preserve `m.scope.Env` if a matching name
  exists in the new project.
- This avoids the previous "vault change → env empty → Tab Tab
  Enter lands on nothing" footgun on narrow screens.

## Focus + tree navigation

Added 2026-06-02:

- Default focus on TUI launch is the **rail**, not content. (An
  empty content pane silently swallowed j/k; users thought arrows
  were broken.)
- `Tab` and `Shift+Tab` toggle focus rail ↔ content.
- `h` / `l` fold/unfold rail nodes. The rail cursor MUST stay where
  the user put it — no auto-snap to the active scope on every
  flatten().
- Auto-snap fires ONLY on:
  - Boot (after envs for the active scope finish loading)
  - Explicit scope changes (Enter on env leaf, scope-picker apply)
- `byn --vault X --project Y --env Z edit` boots into that scope:
  the rail cursor pre-positions on the most specific matching node
  (env > project > vault); the targeted vault's password is prompted
  on bootstrap; the entries list shows that scope.

## Locked-vault UX

Added 2026-06-02:

- When the active scope's vault is locked, `i`/`a`/`r`/`R` all
  refuse with a flash naming the vault and the recovery command:
  `vault "custom" is locked — unlock from a shell first`.
- The ENV-VARS section, when entries-error is `CodeLocked`, renders:
  ```
    Vault is locked
    Run `byn --vault NAME unlock` from a shell, then return.
  ```
  …instead of the misleading `(no env-vars)`.

## Filter visibility

Added 2026-06-02:

- Active `m.entriesFilter` is shown in THREE places so it can never
  be missed:
  1. Warning-colored ENV-VARS header: `filter="custom" (N of M
     match — ESC to clear)`
  2. Persistent chip in the status line: `filter="..."`
  3. Auto-clear flash on `a`: `(cleared active filter)`
- `ESC` from NORMAL clears the active filter (in addition to its
  other roles).
- `a` (start add) auto-clears the filter so the new entry is
  visible after commit.

### VISUAL (Phase B, deferred)

Range selection with `j`/`k` from the cursor for bulk operations
(delete, export). Not in the MVP.

---

## Keymap reference (single source of truth)

Lives at `internal/tui/keymap.go`. Each entry is a `{key, mode,
action, help}` tuple so the HELP overlay can be generated rather than
hand-maintained.

```go
type Binding struct {
    Keys    []string  // bubbletea key string(s)
    Modes   []Mode    // modes in which this binding fires
    Action  Action    // enum the Update loop dispatches
    Section string    // for HELP grouping
    Help    string    // one-line description
}
```

`?` reads the same map to render HELP, so adding a binding in code
adds it to HELP automatically.

---

## Color scheme

Used via `lipgloss`. Honors `NO_COLOR` and `FORCE_COLOR` (same logic
as `color.go`).

| Element | Style |
|---|---|
| Title (top bar app name) | Bold cyan |
| Active rail node (selected) | Bold green |
| Tree branch markers (`▼ ▶`) | Dim |
| Section header (ENV-VARS, FILES, AUDIT) | Bold |
| Section dividers | Dim |
| Masked value bar (`●●●…`) | Dim |
| Hint actions (`+ add (a)`) | Dim italic |
| Selected entry row | Reversed |
| INSERT mode label | Bold cyan |
| REVEALED mode label | Bold red |
| Error / WARNING text | Red |
| Audit `ok` outcome | Green |
| Audit `denied` / `error` outcome | Red |
| Edit-box border | Cyan |
| Detail pane header | Bold |

---

## Data flow

### Boot sequence

1. `runTUI(args)` (the CLI entrypoint) constructs an `ipc.Client` for
   the daemon dir.
2. Calls `OpStatus` to get vault summaries + version info. If daemon
   is down → print recovery message, exit 2 (same as CLI).
3. Initial scope = scope passed from the CLI (after discovery) OR
   default OR first unlocked vault.
4. If active vault is locked: show centered "Vault is locked — press
   u to unlock" overlay; pressing `u` opens a password prompt
   (raw-mode TTY, like the CLI).
5. Once unlocked: load project list + env list + entry list for
   active scope.
6. Start the bubbletea `Program`.

### Refresh triggers

| Trigger | Refresh |
|---|---|
| Scope change | `OpProjectList`, `OpEnvList`, `OpList` for new scope |
| `:w` from INSERT (after OpPut OK) | `OpList` |
| `:w` from ADD-ENTRY | `OpList` |
| Delete confirm | `OpList` |
| Lock / unlock | `OpStatus` |
| `r` in AUDIT view | `OpAuditTail` |
| `Ctrl-l` | Whole refresh (status + projects + envs + entries + audit) |

### Concurrency model

bubbletea runs the model on a single goroutine; commands (`tea.Cmd`)
run in their own goroutines and return `tea.Msg` results. All IPC
calls live in `tea.Cmd`s so the UI never blocks on a slow daemon.

Long-running ops (the unlock prompt's Argon2id) show a spinner.

---

## Browser parity

Same five logical regions, same names:

| TUI region | Browser counterpart |
|---|---|
| Top bar | `<header>` with breadcrumb |
| Rail | `<nav aria-label="Vaults">` sidebar with the same tree |
| Content | `<main>` with the same ENV-VARS / FILES / AUDIT sections |
| Detail | `<aside>` slide-over when an entry is selected |
| Status line | `<footer>` with shortcut hints |

Same vocabulary (vault, project, env, entry, scope, masked, reveal,
audit, doctor, trust). Same data shapes (`scope.Vault`,
`scope.Project`, `scope.Env`, `entries[]`, `audit[]`).

Same operations (add, edit, rename, delete, reveal, copy, import,
export) — each maps to a button/menu item in the browser and a
keybinding here.

When Phase 2 web UI lands, the front-end can be wireframed by reading
this doc.

---

## Package layout

```
internal/tui/
├── tui.go          # Public entry: Run(client, scope, version)
├── model.go        # bubbletea Model: state + Init/Update/View
├── layout.go       # Compute(w, h) Layout
├── keymap.go       # Binding map (source of truth for HELP)
├── style.go        # lipgloss styles + NO_COLOR honor
├── data.go         # IPC wrapper + refresh logic; tea.Cmd helpers
├── rail.go         # Rail pane render + tree navigation
├── content.go      # Content pane render (ENV-VARS / FILES / AUDIT inline)
├── detail.go       # Detail pane render (Large tier)
├── status.go       # Status line render
├── modes/
│   ├── insert.go   # INSERT mode: textarea + commit
│   ├── reveal.go   # REVEAL mode: countdown + audit
│   ├── add.go      # ADD-ENTRY mode: two-field form
│   ├── confirm.go  # CONFIRM-DELETE modal
│   ├── scope.go    # SCOPE picker overlay
│   ├── command.go  # COMMAND palette (`:`)
│   ├── search.go   # SEARCH filter (`/`)
│   ├── audit.go    # AUDIT view (`ga`)
│   └── help.go     # HELP overlay (`?`)
└── tui_test.go     # teatest golden-file snapshots per tier
```

`cmd/byn/cmd_tui.go` shrinks to a 30-line entrypoint that builds
the IPC client and calls `internal/tui.Run`.

---

## Testing strategy

### `teatest` snapshots per tier

```
TestTUI_NormalMode_Tiny      → testdata/normal-tiny.golden
TestTUI_NormalMode_Medium    → testdata/normal-medium.golden
TestTUI_NormalMode_Standard  → testdata/normal-standard.golden
TestTUI_NormalMode_Large     → testdata/normal-large.golden
TestTUI_BelowMin             → testdata/below-min.golden
```

Each test seeds the model with known data and a fixed `WindowSizeMsg`,
calls `Update` to drive to the target screen, then asserts the View
matches the golden. `-update` flag to regenerate.

### Mode-transition tests

Drive a sequence: NORMAL → `i` → INSERT → `:w` → NORMAL (refreshed
list). Use `bubbletea/tea.WithoutSignalHandler()` so the test doesn't
fight the harness.

### Resize tests

Send a sequence of `tea.WindowSizeMsg{80,24}, {120,30}, {50,20}` and
assert the rendered output crosses tier breakpoints cleanly.

### Integration test

Spawn the binary with `BYN_TUI_AUTOCLOSE=1` env var so the TUI
exits on the first idle tick; verify the smoke-test bootstrap works
end-to-end against the real daemon.

---

## Verification checklist (manual smoke per tier)

1. `resize -s 50 24`; launch `byn` → Tiny layout renders, no
   garbled chars, status line visible.
2. `resize -s 75 28`; → Medium with rail.
3. `resize -s 100 30`; → Standard layout (this is the reference).
4. `resize -s 140 40`; → Large with detail pane.
5. While in Standard, `tput cols rows` mid-session to drop to 50; UI
   re-renders to Tiny without flicker, cursor preserved.
6. Repeat with key flows: edit, reveal, add, delete, scope-pick,
   audit view, help. Each must look correct at each tier.
7. Below-min: `resize -s 30 10`; "too small" screen shows, q exits.
