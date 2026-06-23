// Model: the bubbletea Model. Holds all TUI state.
//
// State is broken into:
//   - layout      → from terminal size
//   - mode        → current input mode
//   - focus       → rail vs content
//   - tree        → vault → project → env state, expanded set, cursor
//   - entries     → current scope's entries, cursor
//   - audit       → current vault's recent events
//   - edit        → in-progress INSERT/ADD buffer
//   - reveal      → countdown + decrypted value
//   - cmdline     → COMMAND / SEARCH input buffer
//   - errMsg      → last error to surface in status line
package tui

import (
	"errors"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Mode is the current input mode. Each mode has its own key handler;
// the status line's mode label reflects the active mode.
type Mode int

// Input modes. ModeNormal is the default; the others are entered via
// keybindings (i, a, R, dd, s, :, /, ga, ?) and exited via ESC or a
// mode-specific commit gesture.
const (
	ModeNormal Mode = iota
	ModeInsert
	ModeAdd
	ModeReveal
	ModeConfirmDelete
	ModeScopePicker
	ModeCommand
	ModeSearch
	ModeAudit
	ModeHelp
	ModeRename
	ModeScopeRename
	ModeAuthRequired
)

func (m Mode) String() string {
	switch m {
	case ModeNormal:
		return "NORMAL"
	case ModeInsert:
		return "INSERT"
	case ModeAdd:
		return "INSERT"
	case ModeReveal:
		return "REVEALED"
	case ModeConfirmDelete:
		return "CONFIRM"
	case ModeScopePicker:
		return "SCOPE"
	case ModeCommand:
		return "COMMAND"
	case ModeSearch:
		return "SEARCH"
	case ModeAudit:
		return "AUDIT"
	case ModeHelp:
		return "HELP"
	case ModeRename:
		return "RENAME"
	case ModeScopeRename:
		return "RENAME"
	case ModeAuthRequired:
		return "AUTHORIZE"
	}
	return "?"
}

// Focus is which pane currently consumes navigation keys (j/k/h/l).
type Focus int

// Focus targets — set by Tab in NORMAL mode.
const (
	FocusRail Focus = iota
	FocusContent
	FocusDetail
)

// railNodeKind labels what a rail row represents.
type railNodeKind int

const (
	nodeVault railNodeKind = iota
	nodeProject
	nodeEnv
	nodeNewVault
)

type railNode struct {
	Kind           railNodeKind
	Vault          string
	Project        string
	Env            string
	Depth          int
	IsExpanded     bool
	HasChildren    bool
	IsCurrentScope bool
	Label          string
}

type editBuf struct {
	Name        string // for ADD-ENTRY and RENAME; empty for INSERT on existing
	Value       string
	CursorIdx   int // byte offset; simple model — no UTF-8 cursor math for v1
	OnNameField bool
	OriginalVal string // for INSERT, the pre-edit value; used for dirty + size delta
	IsNew       bool   // ADD-ENTRY vs INSERT
	IsRename    bool   // RENAME variant of edit
	// NameError, when non-empty, blocks commit and triggers red-bordered
	// rendering of the NAME field plus an inline error message under it.
	// Set live as the user types in ADD-ENTRY mode (duplicate detection).
	NameError string

	// Undo / redo history (vi-style, per-snapshot). Capped at maxHistory
	// to keep memory bounded; oldest entries are dropped first.
	History    []editSnapshot
	HistoryPos int // current position in History (len(History) means "live")
}

type editSnapshot struct {
	Name        string
	Value       string
	CursorIdx   int
	OnNameField bool
}

const maxHistory = 200

func (b *editBuf) snapshot() editSnapshot {
	return editSnapshot{
		Name:        b.Name,
		Value:       b.Value,
		CursorIdx:   b.CursorIdx,
		OnNameField: b.OnNameField,
	}
}

// pushHistory records the current state to the undo stack. Called
// BEFORE a mutation so `u` rolls back to the pre-mutation state.
// If the user had un-done some steps and now types fresh, the redo
// tail is dropped (standard vim behavior).
func (b *editBuf) pushHistory() {
	// Trim redo tail.
	if b.HistoryPos < len(b.History) {
		b.History = b.History[:b.HistoryPos]
	}
	b.History = append(b.History, b.snapshot())
	if len(b.History) > maxHistory {
		// Drop oldest.
		b.History = b.History[len(b.History)-maxHistory:]
	}
	b.HistoryPos = len(b.History)
}

// undo restores the previous snapshot. Returns true if there was
// something to undo.
func (b *editBuf) undo() bool {
	if b.HistoryPos == 0 {
		return false
	}
	// If we're at "live" (just after the last push), preserve the
	// current state at the top so redo can return to it.
	if b.HistoryPos == len(b.History) {
		b.History = append(b.History, b.snapshot())
		b.HistoryPos = len(b.History) - 1
	}
	b.HistoryPos--
	s := b.History[b.HistoryPos]
	b.Name = s.Name
	b.Value = s.Value
	b.CursorIdx = s.CursorIdx
	b.OnNameField = s.OnNameField
	return true
}

// redo applies the next snapshot. Returns true if there was a redo
// step available.
func (b *editBuf) redo() bool {
	if b.HistoryPos+1 >= len(b.History) {
		return false
	}
	b.HistoryPos++
	s := b.History[b.HistoryPos]
	b.Name = s.Name
	b.Value = s.Value
	b.CursorIdx = s.CursorIdx
	b.OnNameField = s.OnNameField
	return true
}

// Dirty reports whether the edit buffer holds unsaved changes that
// must either be committed (:w) or explicitly discarded (:q!) before
// the user can exit the edit context. Mirrors vim semantics.
func (b *editBuf) Dirty() bool {
	if b == nil {
		return false
	}
	if b.IsNew {
		// ADD-ENTRY: any typing is dirty (creates a new entry on :w).
		return strings.TrimSpace(b.Name) != "" || b.Value != ""
	}
	if b.IsRename {
		return b.Value != "" && b.Value != b.OriginalVal
	}
	// INSERT: dirty if value differs from what the daemon gave us.
	return b.Value != b.OriginalVal
}

type revealState struct {
	Name       string
	Value      string
	ExpiresAt  time.Time
	Extensions int
}

type cmdlineState struct {
	Prompt string // ":" or "/"
	Input  string
	Cursor int
	// FromEdit is set when COMMAND mode was entered from INSERT/ADD/
	// RENAME so :w / :q / :wq apply edit-scoped semantics (save the
	// in-progress edit and return to NORMAL; cancel and return; etc.)
	// rather than the NORMAL-mode semantics (quit the app).
	FromEdit bool
}

type confirmState struct {
	Name string
	// When Scope is true the confirm deletes a rail node (vault/project/env)
	// rather than the selected entry.
	Scope          bool
	Kind           railNodeKind
	Vault, Project string
}

type scopePickerState struct {
	Column     int // 0=vault, 1=project, 2=env
	VaultIdx   int
	ProjectIdx int
	EnvIdx     int
	Vaults     []string
	Projects   []string
	Envs       []string
}

// Model is the bubbletea Model.
type Model struct {
	// Wiring
	client  Client
	styles  Styles
	version string

	// Layout
	Width, Height int
	Layout        Layout

	// Current input mode + focus
	Mode  Mode
	Focus Focus

	// Status data
	status     ipc.StatusResp
	statusErr  error
	vaultNames []string // sorted vault names from status

	// Tree state
	// expanded["default"] = true | expanded["default/billing"] = true ...
	expanded        map[string]bool
	projectsByVault map[string][]ipc.ProjectInfo
	envsByVaultProj map[string][]ipc.EnvInfo // key = "vault/project"
	railRows        []railNode               // flattened, recomputed when expanded changes
	railCursor      int
	railOffset      int

	// Active scope
	scope ipc.Scope

	// Entries for active scope
	entries       []ipc.SecretMeta
	entriesFilter string // active SEARCH filter
	auditFilter   string // active audit-view filter (client-side, matches any field)
	searchAudit   bool   // the in-progress "/" search targets the audit view, not entries
	auditBefore   int    // audit page cursor: 0 = live newest; >0 = frozen on events with #N below this
	auditMore     bool   // older events exist beyond the current audit page
	entryCursor   int
	entriesErr    error

	// Audit
	audit    []ipc.AuditEvent
	auditErr error

	// defaultEnvNames is the set of entry names that live in the
	// *default* env of the active project. Populated when the active
	// scope's env is non-default so the renderer can tell:
	//   - Source=default       → inherited from default        (↓ dim)
	//   - Source=scope, in def  → overrides default            (⤴ yellow)
	//   - Source=scope, NOT in  → new in this env              (✦ green)
	// When the active env IS default, this map is empty and the
	// renderer hides the column entirely.
	defaultEnvNames map[string]bool

	// Mode-specific state
	edit        *editBuf
	reveal      *revealState
	cmdline     *cmdlineState
	confirm     *confirmState
	picker      *scopePickerState
	scopeRename *scopeRenameState
	authReq     *authReqState

	// Pending key sequence (for 'dd', 'ga', 'gd', etc.)
	pendingKey string

	// Last error/info banner shown in status line
	flashMsg string
	flashOK  bool
}

// NewModel constructs a fresh TUI Model. The IPC client + initial
// scope come from the CLI entrypoint; version is shown in the rail
// header.
func NewModel(client Client, version string, scope ipc.Scope) Model {
	return Model{
		client:  client,
		styles:  NewStyles(),
		version: version,
		scope:   scope,
		Mode:    ModeNormal,
		// Default focus: rail. With an empty content pane on first
		// launch, focusing content silently swallows j/k. Focusing
		// rail makes nav keys work immediately; Tab swaps to content
		// once the user has picked a scope.
		Focus:           FocusRail,
		expanded:        make(map[string]bool),
		projectsByVault: make(map[string][]ipc.ProjectInfo),
		envsByVaultProj: make(map[string][]ipc.EnvInfo),
	}
}

// Init loads the initial vault state.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		loadStatusCmd(m.client),
		loadEntriesCmd(m.client, m.scope),
		loadAuditCmd(m.client, m.scope.Vault, 10),
		tickCmd(time.Second),
	}
	if envOrDefault(m.scope.Env) != "default" {
		cmds = append(cmds, loadDefaultEnvNamesCmd(m.client,
			vaultOrDefault(m.scope.Vault),
			projectOrDefault(m.scope.Project)))
	}
	return tea.Batch(cmds...)
}

// scopeKey returns a "vault/project" key for envsByVaultProj.
func scopeKey(v, p string) string {
	if v == "" {
		v = "default"
	}
	if p == "" {
		p = "default"
	}
	return v + "/" + p
}

// expandKey returns the key under which expanded[] tracks a tree node.
func expandKey(v, p string) string {
	if p == "" {
		return v
	}
	return v + "/" + p
}

// effectiveScope returns scope with empties replaced by "default".
func (m Model) effectiveScope() ipc.Scope {
	s := m.scope
	if s.Vault == "" {
		s.Vault = "default"
	}
	if s.Project == "" {
		s.Project = "default"
	}
	if s.Env == "" {
		s.Env = "default"
	}
	return s
}

// flatten builds railRows from the current tree state. Called whenever
// status/projects/envs change or a node is expanded/collapsed.
func (m *Model) flatten() {
	m.railRows = m.railRows[:0]
	for _, v := range m.vaultNames {
		expanded := m.expanded[expandKey(v, "")]
		m.railRows = append(m.railRows, railNode{
			Kind:           nodeVault,
			Vault:          v,
			Depth:          0,
			IsExpanded:     expanded,
			HasChildren:    true,
			IsCurrentScope: vaultOrDefault(m.scope.Vault) == v,
			Label:          v,
		})
		if !expanded {
			continue
		}
		projects := m.projectsByVault[v]
		for _, p := range projects {
			pExpanded := m.expanded[expandKey(v, p.Name)]
			m.railRows = append(m.railRows, railNode{
				Kind:           nodeProject,
				Vault:          v,
				Project:        p.Name,
				Depth:          1,
				IsExpanded:     pExpanded,
				HasChildren:    true,
				IsCurrentScope: vaultOrDefault(m.scope.Vault) == v && projectOrDefault(m.scope.Project) == p.Name,
				Label:          p.Name,
			})
			if !pExpanded {
				continue
			}
			envs := m.envsByVaultProj[scopeKey(v, p.Name)]
			for _, e := range envs {
				m.railRows = append(m.railRows, railNode{
					Kind:           nodeEnv,
					Vault:          v,
					Project:        p.Name,
					Env:            e.Name,
					Depth:          2,
					IsCurrentScope: vaultOrDefault(m.scope.Vault) == v && projectOrDefault(m.scope.Project) == p.Name && envOrDefault(m.scope.Env) == e.Name,
					Label:          e.Name,
				})
			}
		}
	}
	m.railRows = append(m.railRows, railNode{Kind: nodeNewVault, Label: "+ new vault"})
	if m.railCursor >= len(m.railRows) {
		m.railCursor = len(m.railRows) - 1
	}
	if m.railCursor < 0 {
		m.railCursor = 0
	}
}

// positionRailCursorOnScope moves the rail cursor to the row that
// matches the active scope. Most-specific match wins (env > project >
// vault). Called on initial load and on explicit scope changes — NOT
// on every flatten(), because h/l fold/unfold rebuilds the tree and we
// want the cursor to stay where the user put it.
func (m *Model) positionRailCursorOnScope() {
	for i, r := range m.railRows {
		if r.IsCurrentScope && r.Kind == nodeEnv {
			m.railCursor = i
			return
		}
	}
	for i, r := range m.railRows {
		if r.IsCurrentScope && r.Kind == nodeProject {
			m.railCursor = i
			return
		}
	}
	for i, r := range m.railRows {
		if r.IsCurrentScope && r.Kind == nodeVault {
			m.railCursor = i
			return
		}
	}
}

func vaultOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
func projectOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}
func envOrDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

// scopeDisplay returns "vault/project/env" with defaults filled in.
func (m Model) scopeDisplay() string {
	s := m.effectiveScope()
	return s.Vault + "/" + s.Project + "/" + s.Env
}

// scopeDisplayBreadcrumb returns "vault ▸ project ▸ env".
func (m Model) scopeDisplayBreadcrumb() string {
	s := m.effectiveScope()
	return s.Vault + " ▸ " + s.Project + " ▸ " + s.Env
}

// filteredEntries returns entries matching m.entriesFilter (case-fold).
func (m Model) filteredEntries() []ipc.SecretMeta {
	if m.entriesFilter == "" {
		return m.entries
	}
	q := strings.ToLower(m.entriesFilter)
	out := make([]ipc.SecretMeta, 0, len(m.entries))
	for _, e := range m.entries {
		if strings.Contains(strings.ToLower(e.Name), q) {
			out = append(out, e)
		}
	}
	return out
}

// isVaultLockedErr reports whether err is a daemon "locked" response.
// Used by the content pane to render a clearer message than "no
// env-vars" when the real cause is a locked vault.
func (m Model) isVaultLockedErr(err error) bool {
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		return er.Code == ipc.CodeLocked
	}
	return false
}

// isCurrentVaultLocked reports the lock state of the vault the
// active scope points at, derived from the last OpStatus snapshot.
// Used to short-circuit edit/add gestures with a clear message.
func (m Model) isCurrentVaultLocked() bool {
	name := vaultOrDefault(m.scope.Vault)
	for _, v := range m.status.Vaults {
		if v.Name == name {
			return v.Locked
		}
	}
	// Conservative: if we don't have a status entry, also fall back
	// to the most recent IPC error to avoid blanket-blocking edits
	// when status is just stale.
	return m.entriesErr != nil && m.isVaultLockedErr(m.entriesErr)
}

// vaultLockedByName reports the lock state of a named vault from the last
// status snapshot. Unknown vaults are treated as unlocked.
func (m Model) vaultLockedByName(name string) bool {
	name = vaultOrDefault(name)
	for _, v := range m.status.Vaults {
		if v.Name == name {
			return v.Locked
		}
	}
	return false
}

// authReqState backs ModeAuthRequired: the "Authorize" password overlay shown
// whenever the daemon rejects a value op with CodeAuthRequired. It holds the
// pending op parameters so the retry can re-issue the exact same call with
// the supplied password.
type authReqState struct {
	// Cause is the daemon's human-readable explanation (the ErrResponse.Message).
	// Rendered as the subtitle so the user knows which policy triggered this.
	Cause string

	// buf / cur hold the masked password the user is typing.
	buf []rune
	cur int

	// Retry error (wrong password, etc.) — shown inside the overlay.
	retryErr string

	// Pending op parameters — enough to re-issue each op with a Password.
	// kind matches authRetryKind constants from data.go.
	kind authRetryKind

	// priorMode is the mode the TUI was in when the op was first dispatched.
	// Used to resume the correct destination on retry success (e.g. reveal vs
	// insert prefill).
	priorMode Mode

	// Fields used depending on kind:
	scope ipc.Scope
	name  string // entry name (get/put/delete/rename)
	// value is the put payload (put op).
	// Invariant: value MUST be zeroed on every exit from ModeAuthRequired
	// (esc/cancel, ctrl+c quit, and successful submit). Zeroing on esc/ctrl+c
	// is done in keyAuthRequired; zeroing on submit is done in handleAuthRetry
	// once the retry has completed (successfully or the overlay is dismissed).
	value      []byte
	newName    string // rename new name (rename op)
	createOnly bool   // true when the original add used CreateOnly
}

// scopeRenameState backs ModeScopeRename: an inline rename of a rail node
// (vault / project / env). buf is the editable name; cur is the rune cursor.
type scopeRenameState struct {
	kind           railNodeKind
	vault, project string
	old            string
	buf            []rune
	cur            int
}

// matches reports whether n is the rail node currently being renamed, so the
// rail renderer can draw the input in place.
func (s *scopeRenameState) matches(n railNode) bool {
	if s == nil || s.kind != n.Kind {
		return false
	}
	switch s.kind {
	case nodeVault:
		return s.vault == n.Vault
	case nodeProject:
		return s.vault == n.Vault && s.project == n.Project
	case nodeEnv:
		return s.vault == n.Vault && s.project == n.Project && s.old == n.Env
	}
	return false
}

// scopeNodeName returns the renameable name carried by a rail node.
func scopeNodeName(n railNode) string {
	switch n.Kind {
	case nodeVault:
		return n.Vault
	case nodeProject:
		return n.Project
	case nodeEnv:
		return n.Env
	}
	return ""
}

// EntryStatus is the inheritance status of an entry shown in the
// active env. Used by the renderer to draw a small marker next to
// each row.
type EntryStatus int

// Inheritance states for entries shown in a non-default env. See
// docs/tui-design.md "Inheritance badges".
const (
	StatusNone       EntryStatus = iota // active env is default; no marker
	StatusInherited                     // value comes from default env
	StatusOverridden                    // exists in both; this env's value wins
	StatusNew                           // created in this env, not in default
)

// entryStatus classifies a SecretMeta against the loaded default-env
// names. Returns StatusNone when the active env is itself default,
// when the default-env list hasn't loaded yet, or when the entry's
// state can't be determined.
func (m Model) entryStatus(e ipc.SecretMeta) EntryStatus {
	if envOrDefault(m.scope.Env) == "default" {
		return StatusNone
	}
	if e.Source == "default" {
		return StatusInherited
	}
	// Source == "scope" — distinguish overridden (also in default) from
	// new (not in default). If the default-env list hasn't arrived,
	// don't guess.
	if m.defaultEnvNames == nil {
		return StatusNone
	}
	if m.defaultEnvNames[e.Name] {
		return StatusOverridden
	}
	return StatusNew
}

// currentEntry returns the entry under the entry cursor, if any.
func (m Model) currentEntry() *ipc.SecretMeta {
	es := m.filteredEntries()
	if len(es) == 0 || m.entryCursor < 0 || m.entryCursor >= len(es) {
		return nil
	}
	return &es[m.entryCursor]
}
