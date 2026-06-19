// Update: bubbletea Update method. Folds IPC results into model,
// dispatches keys by mode.
package tui

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Update is the bubbletea Model.Update entrypoint. Folds IPC results
// into model state and dispatches key events by mode.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.Layout = Compute(m.Width, m.Height)
		return m, nil

	case statusLoadedMsg:
		if msg.Err != nil {
			m.statusErr = msg.Err
			return m, nil
		}
		m.status = msg.Resp
		names := make([]string, 0, len(msg.Resp.Vaults))
		for _, v := range msg.Resp.Vaults {
			names = append(names, v.Name)
		}
		sort.Strings(names)
		m.vaultNames = names
		// Auto-expand the current vault so the user sees their tree.
		current := vaultOrDefault(m.scope.Vault)
		m.expanded[expandKey(current, "")] = true
		var cmds []tea.Cmd
		for _, v := range names {
			cmds = append(cmds, loadProjectsCmd(m.client, v))
		}
		m.flatten()
		return m, tea.Batch(cmds...)

	case projectsLoadedMsg:
		if msg.Err == nil {
			m.projectsByVault[msg.Vault] = msg.Resp.Projects
		}
		// Auto-expand the current project under the current vault so
		// envs render under it.
		current := vaultOrDefault(m.scope.Vault)
		if msg.Vault == current {
			m.expanded[expandKey(current, projectOrDefault(m.scope.Project))] = true
		}
		var cmds []tea.Cmd
		for _, p := range msg.Resp.Projects {
			cmds = append(cmds, loadEnvsCmd(m.client, msg.Vault, p.Name))
		}
		m.flatten()
		return m, tea.Batch(cmds...)

	case envsLoadedMsg:
		if msg.Err == nil {
			m.envsByVaultProj[scopeKey(msg.Vault, msg.Project)] = msg.Resp.Envs
		}
		m.flatten()
		// If the envs we just loaded belong to the active scope,
		// snap the rail cursor to that env leaf so initial boot
		// (and post-scope-change refresh) lands the user where they
		// expect. h/l fold/unfold doesn't touch this — only first
		// loads do.
		if msg.Vault == vaultOrDefault(m.scope.Vault) &&
			msg.Project == projectOrDefault(m.scope.Project) {
			m.positionRailCursorOnScope()
		}
		return m, nil

	case entriesLoadedMsg:
		if msg.Err != nil {
			m.entriesErr = msg.Err
			return m, nil
		}
		// Only apply if it matches our current scope (drop stale).
		if msg.Scope.Vault == m.scope.Vault && msg.Scope.Project == m.scope.Project && msg.Scope.Env == m.scope.Env {
			m.entries = msg.Resp.Secrets
			if m.entryCursor >= len(m.entries) {
				m.entryCursor = len(m.entries) - 1
			}
			if m.entryCursor < 0 {
				m.entryCursor = 0
			}
		}
		return m, nil

	case auditLoadedMsg:
		if msg.Err == nil {
			m.audit = msg.Resp.Events
		}
		m.auditErr = msg.Err
		return m, nil

	case defaultEnvLoadedMsg:
		// Only apply if it still matches our active (vault, project).
		// Stale responses from prior scopes are ignored to avoid the
		// renderer flickering against the wrong baseline.
		if msg.Vault == vaultOrDefault(m.scope.Vault) &&
			msg.Project == projectOrDefault(m.scope.Project) &&
			envOrDefault(m.scope.Env) != "default" &&
			msg.Err == nil {
			set := make(map[string]bool, len(msg.Resp.Secrets))
			for _, e := range msg.Resp.Secrets {
				set[e.Name] = true
			}
			m.defaultEnvNames = set
		}
		return m, nil

	case entryValueMsg:
		if msg.Err != nil {
			// auth_required: open the Authorize overlay for a get (reveal/edit).
			if m.isAuthRequired(msg.Err) {
				cause := authRequiredCause(msg.Err)
				m.authReq = &authReqState{
					Cause:     cause,
					kind:      authRetryGet,
					priorMode: m.Mode, // ModeReveal or ModeInsert
					scope:     msg.Scope,
					name:      msg.Name,
				}
				m.Mode = ModeAuthRequired
				return m, nil
			}
			m.flash("get: "+msg.Err.Error(), false)
			return m, nil
		}
		// REVEAL flow: stash the value + start countdown.
		if m.Mode == ModeReveal && m.reveal != nil && m.reveal.Name == msg.Name {
			m.reveal.Value = string(msg.Resp.Value)
			m.reveal.ExpiresAt = time.Now().Add(7 * time.Second)
			return m, nil
		}
		// INSERT-from-existing-entry: prefill the buffer with the
		// real value so the user can edit it.
		if m.Mode == ModeInsert && m.edit != nil && m.edit.Name == msg.Name && m.edit.Value == "" && !m.edit.IsNew {
			m.edit.OriginalVal = string(msg.Resp.Value)
			m.edit.Value = m.edit.OriginalVal
			m.edit.CursorIdx = len(m.edit.Value)
			return m, nil
		}
		return m, nil

	case clipboardYankedMsg:
		if msg.Err != nil {
			m.flash("yank failed: "+msg.Err.Error(), false)
			return m, nil
		}
		m.flash("(yanked "+strconv.Quote(msg.Name)+" → clipboard, "+
			strconv.Itoa(msg.Bytes)+" bytes; reveal in audit log)", true)
		return m, loadAuditCmd(m.client, m.scope.Vault, 10)

	case authRetryMsg:
		return m.handleAuthRetry(msg)

	case opCompleteMsg:
		if msg.Err != nil {
			// auth_required: open the Authorize overlay using the context
			// carried inside the message. The context was captured at dispatch
			// time so a second op dispatched before this response lands cannot
			// clobber it.
			if m.isAuthRequired(msg.Err) && msg.authCtx != nil {
				msg.authCtx.Cause = authRequiredCause(msg.Err)
				m.authReq = msg.authCtx
				m.Mode = ModeAuthRequired
				return m, nil
			}
			// No carried context (shouldn't normally happen) — surface as flash.
			m.authReq = nil
			m.flash(msg.Op+" failed: "+msg.Err.Error(), false)
			return m, nil
		}
		// Success: clear any stale auth context.
		m.authReq = nil
		m.flash(msg.Op+" "+msg.Note+" ok", true)
		return m, tea.Batch(
			loadEntriesCmd(m.client, m.scope),
			loadAuditCmd(m.client, m.scope.Vault, 10),
		)

	case scopeRenamedMsg:
		if msg.Err != nil {
			m.flash("rename failed: "+msg.Err.Error(), false)
			return m, nil
		}
		m.applyScopeRename(msg)
		m.flash("renamed → "+msg.New, true)
		// Reload the tree from the daemon; statusLoadedMsg cascades to
		// reload projects/envs for the (patched) expanded set.
		return m, loadStatusCmd(m.client)

	case scopeChangedMsg:
		if msg.Err != nil {
			m.flash(msg.Err.Error(), false)
			return m, nil
		}
		m.flash(msg.Note, true)
		return m, loadStatusCmd(m.client)

	case tickMsg:
		// REVEAL expiry.
		if m.Mode == ModeReveal && m.reveal != nil {
			if time.Now().After(m.reveal.ExpiresAt) {
				m.Mode = ModeNormal
				m.reveal = nil
				return m, tickCmd(time.Second)
			}
		}
		// Realtime audit: while the full-screen AUDIT view is open, refresh
		// the log every tick so new events (from any surface) stream in.
		if m.Mode == ModeAudit {
			return m, tea.Batch(loadAuditCmd(m.client, m.scope.Vault, 200), tickCmd(time.Second))
		}
		return m, tickCmd(time.Second)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) flash(s string, ok bool) {
	m.flashMsg = s
	m.flashOK = ok
}

// ---- Key handling -------------------------------------------------------

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Mode-specific handlers first.
	switch m.Mode {
	case ModeInsert, ModeAdd, ModeRename:
		return m.keyInsert(msg)
	case ModeScopeRename:
		return m.keyScopeRename(msg)
	case ModeReveal:
		return m.keyReveal(msg)
	case ModeConfirmDelete:
		return m.keyConfirm(msg)
	case ModeScopePicker:
		return m.keyScopePicker(msg)
	case ModeCommand:
		return m.keyCommand(msg)
	case ModeSearch:
		return m.keySearch(msg)
	case ModeAudit:
		return m.keyAudit(msg)
	case ModeHelp:
		return m.keyHelp(msg)
	case ModeAuthRequired:
		return m.keyAuthRequired(msg)
	}
	// NORMAL mode below.
	return m.keyNormal(msg)
}

func (m Model) keyNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()

	// Compose 2-key gestures (dd, ga, gd, gg).
	switch m.pendingKey {
	case "d":
		m.pendingKey = ""
		if k == "d" {
			if m.Focus == FocusRail {
				return m.startScopeDelete()
			}
			if e := m.currentEntry(); e != nil {
				m.Mode = ModeConfirmDelete
				m.confirm = &confirmState{Name: e.Name}
			}
			return m, nil
		}
		// Other key — treat as fresh.
	case "g":
		m.pendingKey = ""
		switch k {
		case "g":
			if m.Focus == FocusContent {
				m.entryCursor = 0
			} else {
				m.railCursor = 0
			}
			return m, nil
		case "a":
			m.Mode = ModeAudit
			return m, loadAuditCmd(m.client, m.scope.Vault, 200)
		case "d":
			// Toggle detail pane on Large (no-op for now)
			return m, nil
		}
	}

	switch k {
	case "ctrl+c":
		return m, tea.Quit
	case "q":
		// Refuse to quit if there's an unsaved edit. Forces the user
		// through :w or :q!.
		if m.edit != nil && m.edit.Dirty() {
			m.flash("unsaved edit — :w to save or :q! to discard", false)
			return m, nil
		}
		return m, tea.Quit
	case "esc":
		// vi-style: ESC from NORMAL clears the active search filter
		// so a stale `/foo` doesn't keep hiding entries silently.
		if m.entriesFilter != "" {
			m.entriesFilter = ""
			m.entryCursor = 0
			m.flash("(filter cleared)", true)
		}
		return m, nil
	case ":":
		m.Mode = ModeCommand
		m.cmdline = &cmdlineState{Prompt: ":", Input: ""}
		return m, nil
	case "/":
		m.Mode = ModeSearch
		m.cmdline = &cmdlineState{Prompt: "/", Input: m.entriesFilter}
		return m, nil
	case "?":
		m.Mode = ModeHelp
		return m, nil
	case "s":
		return m.openScopePicker()
	case "tab":
		// Forward cycle. Only rail and content are focusable today;
		// detail is read-only metadata.
		if m.Focus == FocusRail {
			m.Focus = FocusContent
		} else {
			m.Focus = FocusRail
		}
		return m, nil
	case "shift+tab":
		// Reverse cycle. Symmetric with Tab when there are only two
		// focusable panes; will differ once detail becomes focusable.
		if m.Focus == FocusContent {
			m.Focus = FocusRail
		} else {
			m.Focus = FocusContent
		}
		return m, nil
	case "j", "down":
		return m.cursorMove(+1), nil
	case "k", "up":
		return m.cursorMove(-1), nil
	case "h", "left":
		return m.cursorOut(), nil
	case "l", "right":
		return m.cursorIn(), nil
	case "G":
		if m.Focus == FocusContent {
			m.entryCursor = len(m.filteredEntries()) - 1
			if m.entryCursor < 0 {
				m.entryCursor = 0
			}
		} else {
			m.railCursor = len(m.railRows) - 1
		}
		return m, nil
	case "g":
		m.pendingKey = "g"
		return m, nil
	case "d":
		m.pendingKey = "d"
		return m, nil
	case "enter":
		return m.activate()
	case "i":
		return m.startEdit()
	case "a":
		if m.Focus == FocusRail {
			m.flash("create scopes with `byn project/env create` or the web UI (`byn web`)", false)
			return m, nil
		}
		return m.startAdd()
	case "r":
		if m.Focus == FocusRail {
			return m.startScopeRename()
		}
		return m.startRename()
	case "R":
		return m.startReveal()
	case "u":
		// vi undo on the pending draft. Only meaningful if a buffer
		// exists; otherwise no-op.
		if m.edit == nil {
			m.flash("nothing to undo", false)
			return m, nil
		}
		if m.edit.undo() {
			m.recheckNameError()
		} else {
			m.flash("already at oldest change", false)
		}
		return m, nil
	case "ctrl+r":
		// vi redo (mirrors common modern bindings; classic vim also
		// uses Ctrl-R).
		if m.edit == nil {
			m.flash("nothing to redo", false)
			return m, nil
		}
		if m.edit.redo() {
			m.recheckNameError()
		} else {
			m.flash("already at newest change", false)
		}
		return m, nil
	case "y":
		// Yank: fetch the selected entry's value and write it to the
		// system clipboard. Triggers a daemon-side get + audit event.
		// Result lands as clipboardYankedMsg.
		if m.isCurrentVaultLocked() {
			m.flash("vault is locked — unlock from a shell first", false)
			return m, nil
		}
		e := m.currentEntry()
		if e == nil {
			m.flash("no entry selected to yank", false)
			return m, nil
		}
		return m, yankToClipboardCmd(m.client, m.scope, e.Name)
	case "p":
		// Paste from system clipboard. Only meaningful when an edit
		// buffer is open (resumed draft); pastes at cursor in the
		// value field. If no draft is open we can't paste anywhere
		// meaningful — open one via `i` first.
		if m.edit == nil {
			m.flash("nothing to paste into — press `i` to edit first", false)
			return m, nil
		}
		pasted, err := clipboard.ReadAll()
		if err != nil {
			m.flash("clipboard read failed: "+err.Error(), false)
			return m, nil
		}
		if pasted == "" {
			m.flash("clipboard is empty", false)
			return m, nil
		}
		m.edit.pushHistory()
		m.edit.Value = m.edit.Value[:m.edit.CursorIdx] + pasted + m.edit.Value[m.edit.CursorIdx:]
		m.edit.CursorIdx += len(pasted)
		m.flash("(pasted "+strconv.Itoa(len(pasted))+" bytes from clipboard)", true)
		return m, nil
	}
	m.pendingKey = ""
	return m, nil
}

// cursorMove moves the cursor of the focused pane by delta.
func (m Model) cursorMove(delta int) Model {
	if m.Focus == FocusRail {
		m.railCursor += delta
		if m.railCursor < 0 {
			m.railCursor = 0
		}
		if m.railCursor >= len(m.railRows) {
			m.railCursor = len(m.railRows) - 1
		}
		return m
	}
	es := m.filteredEntries()
	m.entryCursor += delta
	if m.entryCursor < 0 {
		m.entryCursor = 0
	}
	if m.entryCursor >= len(es) {
		m.entryCursor = len(es) - 1
	}
	if m.entryCursor < 0 {
		m.entryCursor = 0
	}
	return m
}

// cursorIn / cursorOut handle h/l in the focused pane.
func (m Model) cursorIn() Model {
	if m.Focus == FocusRail && len(m.railRows) > 0 {
		node := m.railRows[m.railCursor]
		if node.HasChildren && !node.IsExpanded {
			key := expandKey(node.Vault, node.Project)
			m.expanded[key] = true
			m.flatten()
		}
	}
	return m
}

func (m Model) cursorOut() Model {
	if m.Focus == FocusRail && len(m.railRows) > 0 {
		node := m.railRows[m.railCursor]
		if node.HasChildren && node.IsExpanded {
			key := expandKey(node.Vault, node.Project)
			delete(m.expanded, key)
			m.flatten()
		}
	}
	return m
}

// activate handles Enter — rail leaf jumps scope; content row reveals
// or opens edit depending on context.
func (m Model) activate() (tea.Model, tea.Cmd) {
	if m.Focus == FocusRail && len(m.railRows) > 0 {
		node := m.railRows[m.railCursor]
		switch node.Kind {
		case nodeVault:
			m.scope = ipc.Scope{Vault: node.Vault}
			return m.loadCurrentScope()
		case nodeProject:
			m.scope = ipc.Scope{Vault: node.Vault, Project: node.Project}
			return m.loadCurrentScope()
		case nodeEnv:
			m.scope = ipc.Scope{Vault: node.Vault, Project: node.Project, Env: node.Env}
			return m.loadCurrentScope()
		case nodeNewVault:
			m.flash("create a vault with `byn init --vault NAME` or the web UI (`byn web`)", false)
			return m, nil
		}
	}
	// Content: Enter on a row opens INSERT.
	return m.startEdit()
}

// loadCurrentScope kicks off a refresh after a scope change. Also
// fetches the default-env names for the same (vault, project) when
// the active env is non-default — that's what powers the inherited /
// overridden / new markers on each entry row.
func (m Model) loadCurrentScope() (tea.Model, tea.Cmd) {
	m.flatten()
	m.entries = nil
	m.entryCursor = 0
	m.defaultEnvNames = nil
	cmds := []tea.Cmd{
		loadEntriesCmd(m.client, m.scope),
		loadAuditCmd(m.client, m.scope.Vault, 10),
	}
	if envOrDefault(m.scope.Env) != "default" {
		cmds = append(cmds,
			loadDefaultEnvNamesCmd(m.client,
				vaultOrDefault(m.scope.Vault),
				projectOrDefault(m.scope.Project)))
	}
	return m, tea.Batch(cmds...)
}

// startEdit transitions to INSERT for the current entry. If a draft
// for the same entry already exists, resume it instead of re-fetching
// from the daemon. If a dirty draft exists for a DIFFERENT entry, refuse
// — the user must :w or :q! the existing draft first.
func (m Model) startEdit() (tea.Model, tea.Cmd) {
	if m.isCurrentVaultLocked() {
		m.flash("vault "+strconv.Quote(vaultOrDefault(m.scope.Vault))+
			" is locked — unlock from a shell first", false)
		return m, nil
	}
	e := m.currentEntry()
	if e == nil {
		m.flash("no entry selected (use `a` to add)", false)
		return m, nil
	}
	// Resume existing draft for the same entry.
	if m.edit != nil && m.edit.Name == e.Name && !m.edit.IsNew && !m.edit.IsRename {
		m.Mode = ModeInsert
		return m, nil
	}
	if m.edit != nil && m.edit.Dirty() {
		owner := m.edit.Name
		if m.edit.IsNew {
			owner = "(new entry)"
		}
		m.flash("unsaved draft on "+strconv.Quote(owner)+" — :w or :q! first", false)
		return m, nil
	}
	m.Mode = ModeInsert
	m.edit = &editBuf{Name: e.Name, IsNew: false}
	// Fetch the current value to prefill the buffer.
	return m, getValueCmd(m.client, m.scope, e.Name)
}

func (m Model) startAdd() (tea.Model, tea.Cmd) {
	if m.isCurrentVaultLocked() {
		m.flash("vault "+strconv.Quote(vaultOrDefault(m.scope.Vault))+
			" is locked — unlock from a shell first", false)
		return m, nil
	}
	if m.edit != nil && m.edit.Dirty() {
		m.flash("unsaved edit — :w or :q! first", false)
		return m, nil
	}
	m.Mode = ModeAdd
	m.edit = &editBuf{IsNew: true, OnNameField: true}
	// Clear any active search filter so the freshly-added entry will
	// be visible in the list after commit. Otherwise a stray `/foo`
	// filter from earlier hides the new entry and the user thinks
	// the add silently failed.
	if m.entriesFilter != "" {
		m.entriesFilter = ""
		m.flash("(cleared active filter)", true)
	}
	return m, nil
}

func (m Model) startRename() (tea.Model, tea.Cmd) {
	if m.isCurrentVaultLocked() {
		m.flash("vault is locked — unlock from a shell first", false)
		return m, nil
	}
	if m.edit != nil && m.edit.Dirty() {
		m.flash("unsaved edit — :w or :q! first", false)
		return m, nil
	}
	e := m.currentEntry()
	if e == nil {
		return m, nil
	}
	m.Mode = ModeRename
	m.edit = &editBuf{Name: e.Name, Value: e.Name, OriginalVal: e.Name, OnNameField: true, IsRename: true}
	m.edit.CursorIdx = len(m.edit.Value)
	return m, nil
}

// startScopeRename begins an inline rename of the selected rail node (a
// vault, project, or env). The default vault/project/env are protected, and
// a locked vault must be unlocked first (the TUI doesn't prompt for the
// password mid-rename).
func (m Model) startScopeRename() (tea.Model, tea.Cmd) {
	if len(m.railRows) == 0 || m.railCursor < 0 || m.railCursor >= len(m.railRows) {
		return m, nil
	}
	node := m.railRows[m.railCursor]
	switch node.Kind {
	case nodeVault:
		if vaultOrDefault(node.Vault) == "default" {
			m.flash("the default vault can't be renamed", false)
			return m, nil
		}
	case nodeProject:
		if node.Project == "default" {
			m.flash("the default project can't be renamed", false)
			return m, nil
		}
	case nodeEnv:
		if node.Env == "default" {
			m.flash("the default env can't be renamed", false)
			return m, nil
		}
	default:
		return m, nil // nodeNewVault
	}
	if m.vaultLockedByName(node.Vault) {
		m.flash("vault is locked — unlock from a shell first", false)
		return m, nil
	}
	name := scopeNodeName(node)
	m.scopeRename = &scopeRenameState{
		kind: node.Kind, vault: node.Vault, project: node.Project,
		old: name, buf: []rune(name), cur: len([]rune(name)),
	}
	m.Mode = ModeScopeRename
	return m, nil
}

// startScopeDelete opens a confirm to delete the selected rail node (vault/
// project/env). The default scopes are protected; a locked vault must be
// unlocked first.
func (m Model) startScopeDelete() (tea.Model, tea.Cmd) {
	if len(m.railRows) == 0 || m.railCursor < 0 || m.railCursor >= len(m.railRows) {
		return m, nil
	}
	node := m.railRows[m.railCursor]
	switch node.Kind {
	case nodeVault:
		if vaultOrDefault(node.Vault) == "default" {
			m.flash("the default vault can't be deleted", false)
			return m, nil
		}
	case nodeProject:
		if node.Project == "default" {
			m.flash("the default project can't be deleted", false)
			return m, nil
		}
	case nodeEnv:
		if node.Env == "default" {
			m.flash("the default env can't be deleted", false)
			return m, nil
		}
	default:
		return m, nil // nodeNewVault
	}
	if m.vaultLockedByName(node.Vault) {
		m.flash("vault is locked — unlock from a shell first", false)
		return m, nil
	}
	m.Mode = ModeConfirmDelete
	m.confirm = &confirmState{
		Name: scopeNodeName(node), Scope: true,
		Kind: node.Kind, Vault: node.Vault, Project: node.Project,
	}
	return m, nil
}

// clearScopeIfDeleted resets the active scope up one level when the scope it
// points at is the one being deleted, so the post-delete reload doesn't try
// to load a vanished scope.
func (m *Model) clearScopeIfDeleted(cf *confirmState) {
	switch cf.Kind {
	case nodeVault:
		if vaultOrDefault(m.scope.Vault) == cf.Name {
			m.scope = ipc.Scope{}
		}
	case nodeProject:
		if vaultOrDefault(m.scope.Vault) == cf.Vault && projectOrDefault(m.scope.Project) == cf.Name {
			m.scope = ipc.Scope{Vault: cf.Vault}
		}
	case nodeEnv:
		if vaultOrDefault(m.scope.Vault) == cf.Vault && projectOrDefault(m.scope.Project) == cf.Project && envOrDefault(m.scope.Env) == cf.Name {
			m.scope = ipc.Scope{Vault: cf.Vault, Project: cf.Project}
		}
	}
}

// scopeKindLabel names a rail node kind for confirm/flash messages.
func scopeKindLabel(k railNodeKind) string {
	switch k {
	case nodeVault:
		return "vault"
	case nodeProject:
		return "project"
	case nodeEnv:
		return "env"
	}
	return "scope"
}

// keyScopeRename handles input while renaming a rail node inline.
func (m Model) keyScopeRename(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	sr := m.scopeRename
	if sr == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc":
		m.scopeRename = nil
		m.Mode = ModeNormal
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "enter":
		newName := strings.TrimSpace(string(sr.buf))
		kind, vlt, prj, old := sr.kind, sr.vault, sr.project, sr.old
		m.scopeRename = nil
		m.Mode = ModeNormal
		if newName == "" || newName == old {
			return m, nil
		}
		return m, scopeRenameCmd(m.client, kind, vlt, prj, old, newName)
	case "left":
		if sr.cur > 0 {
			sr.cur--
		}
		return m, nil
	case "right":
		if sr.cur < len(sr.buf) {
			sr.cur++
		}
		return m, nil
	case "home", "ctrl+a":
		sr.cur = 0
		return m, nil
	case "end", "ctrl+e":
		sr.cur = len(sr.buf)
		return m, nil
	case "backspace":
		if sr.cur > 0 {
			sr.buf = append(sr.buf[:sr.cur-1], sr.buf[sr.cur:]...)
			sr.cur--
		}
		return m, nil
	default:
		if rs := msg.Runes; len(rs) > 0 {
			tail := append([]rune{}, sr.buf[sr.cur:]...)
			sr.buf = append(append(sr.buf[:sr.cur], rs...), tail...)
			sr.cur += len(rs)
		}
		return m, nil
	}
}

// applyScopeRename patches the cached tree state so a renamed vault/project/
// env keeps its expansion and stays the active scope across the reload.
func (m *Model) applyScopeRename(msg scopeRenamedMsg) {
	switch msg.Kind {
	case nodeVault:
		renameExpandedPrefix(m.expanded, msg.Old, msg.New)
		delete(m.projectsByVault, msg.Old)
		for k := range m.envsByVaultProj {
			if k == msg.Old || strings.HasPrefix(k, msg.Old+"/") {
				delete(m.envsByVaultProj, k)
			}
		}
		if m.scope.Vault == msg.Old {
			// The renamed vault is now locked; point the scope at it and
			// drop the project/env (re-navigate after unlocking).
			m.scope = ipc.Scope{Vault: msg.New}
		}
	case nodeProject:
		oldKey := msg.Vault + "/" + msg.Old
		newKey := msg.Vault + "/" + msg.New
		if m.expanded[oldKey] {
			delete(m.expanded, oldKey)
			m.expanded[newKey] = true
		}
		delete(m.projectsByVault, msg.Vault) // force reload
		delete(m.envsByVaultProj, oldKey)
		if m.scope.Vault == msg.Vault && m.scope.Project == msg.Old {
			m.scope.Project = msg.New
		}
	case nodeEnv:
		delete(m.envsByVaultProj, msg.Vault+"/"+msg.Project) // force reload
		if m.scope.Vault == msg.Vault && m.scope.Project == msg.Project && m.scope.Env == msg.Old {
			m.scope.Env = msg.New
		}
	}
}

// renameExpandedPrefix re-keys expanded entries from old (and old/...) to
// new, preserving their boolean state.
func renameExpandedPrefix(exp map[string]bool, old, neu string) {
	type kv struct {
		k string
		v bool
	}
	var adds []kv
	for k, v := range exp {
		switch {
		case k == old:
			delete(exp, k)
			adds = append(adds, kv{neu, v})
		case strings.HasPrefix(k, old+"/"):
			delete(exp, k)
			adds = append(adds, kv{neu + k[len(old):], v})
		}
	}
	for _, a := range adds {
		exp[a.k] = a.v
	}
}

func (m Model) startReveal() (tea.Model, tea.Cmd) {
	if m.isCurrentVaultLocked() {
		m.flash("vault is locked — unlock from a shell first", false)
		return m, nil
	}
	e := m.currentEntry()
	if e == nil {
		return m, nil
	}
	m.Mode = ModeReveal
	m.reveal = &revealState{Name: e.Name, ExpiresAt: time.Now().Add(7 * time.Second)}
	return m, getValueCmd(m.client, m.scope, e.Name)
}

// ---- INSERT mode --------------------------------------------------------

func (m Model) keyInsert(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := msg.String()
	if m.edit == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch k {
	case "esc":
		// vim semantics: ESC leaves keystroke mode but the buffer
		// stays. The user must explicitly :w to commit or :q! to
		// discard. We drop back to NORMAL TUI mode so they can
		// navigate, but the entry shows a [draft] indicator and
		// :q from NORMAL refuses if any draft is dirty.
		m.Mode = ModeNormal
		if m.edit != nil && m.edit.Dirty() {
			m.flash("unsaved edit — :w to save, :q! to discard, :wq to save+exit", false)
		} else {
			m.edit = nil
		}
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case ":":
		// Command palette from an edit context. :w / :q / :q! / :wq
		// route through runCommand with FromEdit set so they apply
		// edit-scoped semantics.
		m.Mode = ModeCommand
		m.cmdline = &cmdlineState{Prompt: ":", Input: "", FromEdit: true}
		return m, nil
	case "tab", "shift+tab":
		// Two-field form: NAME ↔ VALUE. Tab and Shift+Tab both toggle
		// (with two fields they're symmetric; once a future third
		// field lands we'll branch on the key).
		if m.Mode == ModeAdd {
			m.edit.OnNameField = !m.edit.OnNameField
			m.edit.CursorIdx = len(m.activeField())
		}
		return m, nil
	case "enter":
		// In ADD-ENTRY: Enter on name field advances to value field
		// (names are single-line identifiers). Enter on the value
		// field inserts a literal newline so multi-line secrets
		// (PEM keys, etc.) are editable. In RENAME, Enter does NOT
		// commit either — that's :w in vim.
		if m.Mode == ModeAdd && m.edit.OnNameField {
			m.edit.OnNameField = false
			m.edit.CursorIdx = len(m.edit.Value)
			return m, nil
		}
		if m.Mode == ModeRename {
			// Names are single-line; ignore Enter rather than insert
			// a newline into a name buffer.
			return m, nil
		}
		// INSERT or ADD value field: insert a newline character.
		m.edit.pushHistory()
		m.edit.Value = m.edit.Value[:m.edit.CursorIdx] + "\n" + m.edit.Value[m.edit.CursorIdx:]
		m.edit.CursorIdx++
		return m, nil
	case "backspace":
		if m.edit.CursorIdx > 0 {
			m.edit.pushHistory()
		}
		if m.edit.OnNameField || m.Mode == ModeRename {
			if m.edit.CursorIdx > 0 {
				m.edit.Name = m.edit.Name[:m.edit.CursorIdx-1] + m.edit.Name[m.edit.CursorIdx:]
				if m.Mode == ModeRename {
					m.edit.Value = m.edit.Name
				}
				m.edit.CursorIdx--
			}
		} else {
			if m.edit.CursorIdx > 0 {
				m.edit.Value = m.edit.Value[:m.edit.CursorIdx-1] + m.edit.Value[m.edit.CursorIdx:]
				m.edit.CursorIdx--
			}
		}
		m.recheckNameError()
		return m, nil
	case "ctrl+v":
		// Paste from system clipboard at cursor. Mirrors the common
		// terminal-app convention; vi-style `p` lives in NORMAL mode.
		if !m.edit.OnNameField && m.Mode != ModeRename {
			pasted, err := clipboard.ReadAll()
			if err == nil && pasted != "" {
				m.edit.pushHistory()
				m.edit.Value = m.edit.Value[:m.edit.CursorIdx] + pasted + m.edit.Value[m.edit.CursorIdx:]
				m.edit.CursorIdx += len(pasted)
			} else if err != nil {
				m.flash("clipboard: "+err.Error(), false)
			}
		}
		return m, nil
	case "left":
		if m.edit.CursorIdx > 0 {
			m.edit.CursorIdx--
		}
		return m, nil
	case "right":
		field := m.activeField()
		if m.edit.CursorIdx < len(field) {
			m.edit.CursorIdx++
		}
		return m, nil
	case "home":
		m.edit.CursorIdx = 0
		return m, nil
	case "end":
		m.edit.CursorIdx = len(m.activeField())
		return m, nil
	}
	// Plain text input: append rune(s)
	if len(msg.Runes) > 0 {
		s := string(msg.Runes)
		m.edit.pushHistory()
		if m.edit.OnNameField || m.Mode == ModeRename {
			m.edit.Name = m.edit.Name[:m.edit.CursorIdx] + s + m.edit.Name[m.edit.CursorIdx:]
			if m.Mode == ModeRename {
				m.edit.Value = m.edit.Name
			}
			m.edit.CursorIdx += len(s)
		} else {
			m.edit.Value = m.edit.Value[:m.edit.CursorIdx] + s + m.edit.Value[m.edit.CursorIdx:]
			m.edit.CursorIdx += len(s)
		}
	}
	// After every keystroke that touched the NAME field, re-validate.
	m.recheckNameError()
	return m, nil
}

// recheckNameError refreshes m.edit.NameError based on the current
// buffer. Only fires in ADD-ENTRY mode; INSERT (existing entry) and
// RENAME use different validity rules.
func (m *Model) recheckNameError() {
	if m.edit == nil || m.Mode != ModeAdd {
		return
	}
	name := strings.TrimSpace(m.edit.Name)
	if name == "" {
		m.edit.NameError = ""
		return
	}
	for _, e := range m.entries {
		if e.Name == name {
			m.edit.NameError = "name already exists in " + m.scopeDisplay()
			return
		}
	}
	m.edit.NameError = ""
}

// activeField returns the currently-edited string slice (for cursor math).
func (m Model) activeField() string {
	if m.edit == nil {
		return ""
	}
	if m.edit.OnNameField || m.Mode == ModeRename {
		return m.edit.Name
	}
	return m.edit.Value
}

func (m Model) commitEdit() (tea.Model, tea.Cmd) {
	if m.edit == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch m.Mode {
	case ModeAdd:
		name := strings.TrimSpace(m.edit.Name)
		if name == "" {
			m.flash("name required", false)
			return m, nil
		}
		// Live-validated NameError already covers duplicate detection
		// (set on every keystroke). Re-check once here too so a race
		// with another writer doesn't slip through, then bail with
		// the inline error visible in the form.
		m.recheckNameError()
		if m.edit.NameError != "" {
			m.flash(strconv.Quote(name)+": "+m.edit.NameError, false)
			return m, nil
		}
		val := []byte(m.edit.Value)
		scope := m.scope
		m.edit = nil
		m.Mode = ModeNormal
		// Capture the auth-retry context at dispatch time and carry it
		// inside the message so a second op dispatched before this result
		// lands cannot overwrite the pending context on the model.
		ctx := &authReqState{
			kind: authRetryPut, scope: scope, name: name, value: val, createOnly: true,
		}
		// CreateOnly=true on the daemon side catches the racy case
		// where another writer added the same name between our list
		// fetch and our put.
		return m, addEntryCmd(m.client, scope, name, val, ctx)
	case ModeInsert:
		name := m.edit.Name
		val := []byte(m.edit.Value)
		scope := m.scope
		m.edit = nil
		m.Mode = ModeNormal
		ctx := &authReqState{
			kind: authRetryPut, scope: scope, name: name, value: val,
		}
		return m, putValueCmd(m.client, scope, name, val, ctx)
	case ModeRename:
		// OriginalVal holds the entry's name before the user started
		// editing. Name/Value are both mutated in place as the user
		// types, so OriginalVal is the reliable source of the old name.
		old := m.edit.OriginalVal
		// Value mirrors Name during rename editing; use Value for the new name.
		newName := m.edit.Value
		scope := m.scope
		m.edit = nil
		m.Mode = ModeNormal
		if old == newName || strings.TrimSpace(newName) == "" {
			return m, nil
		}
		ctx := &authReqState{
			kind: authRetryRename, scope: scope, name: old, newName: newName,
		}
		return m, renameEntryCmd(m.client, scope, old, newName, ctx)
	}
	return m, nil
}

// ---- REVEAL mode --------------------------------------------------------

func (m Model) keyReveal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.Mode = ModeNormal
		m.reveal = nil
		return m, nil
	case "R":
		if m.reveal != nil {
			m.reveal.ExpiresAt = time.Now().Add(7 * time.Second)
			m.reveal.Extensions++
		}
		return m, nil
	case "y":
		// Copy the revealed value to the system clipboard.
		if m.reveal != nil && m.reveal.Value != "" {
			if err := clipboardWrite(m.reveal.Value); err != nil {
				m.flash("clipboard write failed: "+err.Error(), false)
				return m, nil
			}
			m.flash("(copied "+strconv.Itoa(len(m.reveal.Value))+" bytes to clipboard)", true)
		} else {
			m.flash("value not yet revealed — wait for ⏱", false)
		}
		return m, nil
	case "e":
		if m.reveal != nil {
			name := m.reveal.Name
			m.Mode = ModeInsert
			m.edit = &editBuf{Name: name, Value: m.reveal.Value, CursorIdx: len(m.reveal.Value), OriginalVal: m.reveal.Value}
			m.reveal = nil
		}
		return m, nil
	}
	return m, nil
}

// ---- CONFIRM-DELETE -----------------------------------------------------

func (m Model) keyConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "d":
		if m.confirm == nil {
			m.Mode = ModeNormal
			return m, nil
		}
		cf := m.confirm
		m.confirm = nil
		m.Mode = ModeNormal
		if cf.Scope {
			m.clearScopeIfDeleted(cf)
			return m, scopeDeleteCmd(m.client, cf.Kind, cf.Vault, cf.Project, cf.Name)
		}
		scope := m.scope
		name := cf.Name
		ctx := &authReqState{
			kind: authRetryDelete, scope: scope, name: name,
		}
		return m, deleteEntryCmd(m.client, scope, name, ctx)
	case "esc", "q", "n":
		m.confirm = nil
		m.Mode = ModeNormal
		return m, nil
	}
	return m, nil
}

// ---- SCOPE picker -------------------------------------------------------

func (m Model) openScopePicker() (tea.Model, tea.Cmd) {
	v := vaultOrDefault(m.scope.Vault)
	p := projectOrDefault(m.scope.Project)
	pi := 0
	vi := 0
	for i, n := range m.vaultNames {
		if n == v {
			vi = i
		}
	}
	projs := m.projectsByVault[v]
	projNames := make([]string, len(projs))
	for i, pp := range projs {
		projNames[i] = pp.Name
		if pp.Name == p {
			pi = i
		}
	}
	envs := m.envsByVaultProj[scopeKey(v, p)]
	envNames := make([]string, len(envs))
	ei := 0
	for i, ee := range envs {
		envNames[i] = ee.Name
		if ee.Name == envOrDefault(m.scope.Env) {
			ei = i
		}
	}
	m.picker = &scopePickerState{
		Column:     0,
		VaultIdx:   vi,
		ProjectIdx: pi,
		EnvIdx:     ei,
		Vaults:     append([]string{}, m.vaultNames...),
		Projects:   projNames,
		Envs:       envNames,
	}
	m.Mode = ModeScopePicker
	return m, nil
}

func (m Model) keyScopePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.picker == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc", "q":
		m.picker = nil
		m.Mode = ModeNormal
		return m, nil
	case "tab", "right", "l":
		m.picker.Column = (m.picker.Column + 1) % 3
		return m, nil
	case "shift+tab", "left", "h":
		m.picker.Column = (m.picker.Column + 2) % 3
		return m, nil
	case "j", "down":
		m.scopePickerMove(+1)
		return m, m.scopePickerCascade()
	case "k", "up":
		m.scopePickerMove(-1)
		return m, m.scopePickerCascade()
	case "enter":
		v, p, e := m.scopePickerSelection()
		m.scope = ipc.Scope{Vault: v, Project: p, Env: e}
		m.picker = nil
		m.Mode = ModeNormal
		return m.loadCurrentScope()
	}
	return m, nil
}

func (m *Model) scopePickerMove(delta int) {
	clamp := func(i, n int) int {
		if n == 0 {
			return 0
		}
		if i < 0 {
			return 0
		}
		if i >= n {
			return n - 1
		}
		return i
	}
	switch m.picker.Column {
	case 0:
		m.picker.VaultIdx = clamp(m.picker.VaultIdx+delta, len(m.picker.Vaults))
	case 1:
		m.picker.ProjectIdx = clamp(m.picker.ProjectIdx+delta, len(m.picker.Projects))
	case 2:
		m.picker.EnvIdx = clamp(m.picker.EnvIdx+delta, len(m.picker.Envs))
	}
}

func (m Model) scopePickerSelection() (v, p, e string) {
	if m.picker == nil {
		return "", "", ""
	}
	if m.picker.VaultIdx < len(m.picker.Vaults) {
		v = m.picker.Vaults[m.picker.VaultIdx]
	}
	if m.picker.ProjectIdx < len(m.picker.Projects) {
		p = m.picker.Projects[m.picker.ProjectIdx]
	}
	if m.picker.EnvIdx < len(m.picker.Envs) {
		e = m.picker.Envs[m.picker.EnvIdx]
	}
	return
}

// scopePickerCascade refreshes the projects/envs lists when the user
// moves the cursor in the vault or project column so all three columns
// stay coherent. After a vault move we also rebuild the env list using
// the (now reset) Projects[0] as parent — otherwise a Tab to the env
// column would land on an empty list and force the user to detour
// through the project column just to repopulate envs.
func (m Model) scopePickerCascade() tea.Cmd {
	if m.picker == nil {
		return nil
	}
	switch m.picker.Column {
	case 0:
		if m.picker.VaultIdx < len(m.picker.Vaults) {
			v := m.picker.Vaults[m.picker.VaultIdx]
			projs := m.projectsByVault[v]
			projNames := make([]string, len(projs))
			for i, p := range projs {
				projNames[i] = p.Name
			}
			m.picker.Projects = projNames
			// Try to keep the user's current project selection if a
			// project of the same name exists in the new vault.
			m.picker.ProjectIdx = 0
			currentProject := projectOrDefault(m.scope.Project)
			for i, p := range projNames {
				if p == currentProject {
					m.picker.ProjectIdx = i
					break
				}
			}
			// Cascade through to envs using the selected project so
			// the env column is populated as soon as the user moves
			// the vault cursor — no detour through the project col.
			if m.picker.ProjectIdx < len(projNames) {
				selectedProject := projNames[m.picker.ProjectIdx]
				envs := m.envsByVaultProj[scopeKey(v, selectedProject)]
				envNames := make([]string, len(envs))
				m.picker.EnvIdx = 0
				currentEnv := envOrDefault(m.scope.Env)
				for i, e := range envs {
					envNames[i] = e.Name
					if e.Name == currentEnv {
						m.picker.EnvIdx = i
					}
				}
				m.picker.Envs = envNames
			} else {
				m.picker.Envs = nil
				m.picker.EnvIdx = 0
			}
		}
	case 1:
		if m.picker.VaultIdx < len(m.picker.Vaults) && m.picker.ProjectIdx < len(m.picker.Projects) {
			v := m.picker.Vaults[m.picker.VaultIdx]
			p := m.picker.Projects[m.picker.ProjectIdx]
			envs := m.envsByVaultProj[scopeKey(v, p)]
			names := make([]string, len(envs))
			for i, e := range envs {
				names[i] = e.Name
			}
			m.picker.Envs = names
			m.picker.EnvIdx = 0
		}
	}
	return nil
}

// ---- COMMAND mode -------------------------------------------------------

func (m Model) keyCommand(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.cmdline == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc":
		// Cancel the command palette. If we came from an edit, leave
		// the buffer intact so the user can continue editing.
		fromEdit := m.cmdline.FromEdit
		m.cmdline = nil
		if fromEdit && m.edit != nil {
			// Return to whichever edit mode the buffer belongs to.
			if m.edit.IsNew {
				m.Mode = ModeAdd
			} else {
				m.Mode = ModeInsert
			}
		} else {
			m.Mode = ModeNormal
		}
		return m, nil
	case "enter":
		input := m.cmdline.Input
		fromEdit := m.cmdline.FromEdit
		m.cmdline = nil
		// Default mode after running a command. runCommand can
		// override (e.g., :w from INSERT goes back to NORMAL after
		// commit; :wq still goes to NORMAL).
		m.Mode = ModeNormal
		return m.runCommand(input, fromEdit)
	case "backspace":
		if len(m.cmdline.Input) > 0 {
			m.cmdline.Input = m.cmdline.Input[:len(m.cmdline.Input)-1]
		}
		return m, nil
	}
	if len(msg.Runes) > 0 {
		m.cmdline.Input += string(msg.Runes)
	}
	return m, nil
}

func (m Model) runCommand(input string, fromEdit bool) (tea.Model, tea.Cmd) {
	args := strings.Fields(input)
	if len(args) == 0 {
		return m, nil
	}
	// vim-style commands. They behave differently from an edit context
	// (FromEdit=true) versus from the NORMAL list view. Critical
	// safety: :q refuses to discard a dirty buffer; :q! always does.
	hasDirtyDraft := m.edit != nil && m.edit.Dirty()
	switch args[0] {
	case "w":
		if m.edit != nil {
			switch {
			case m.edit.IsNew:
				m.Mode = ModeAdd
			case m.edit.IsRename:
				m.Mode = ModeRename
			default:
				m.Mode = ModeInsert
			}
			return m.commitEdit()
		}
		m.flash("nothing to save", false)
		return m, nil
	case "q", "quit":
		if hasDirtyDraft {
			m.flash("unsaved edit — :w to save or :q! to discard", false)
			return m, nil
		}
		// Either no draft at all or a non-dirty draft; both can be
		// dropped without losing user work.
		m.edit = nil
		if fromEdit {
			// Just leave the edit context; stay in the TUI.
			return m, nil
		}
		return m, tea.Quit
	case "q!":
		m.edit = nil
		if fromEdit {
			m.flash("(edit discarded)", true)
			return m, nil
		}
		return m, tea.Quit
	case "wq":
		if m.edit != nil {
			switch {
			case m.edit.IsNew:
				m.Mode = ModeAdd
			case m.edit.IsRename:
				m.Mode = ModeRename
			default:
				m.Mode = ModeInsert
			}
			// commitEdit returns to NORMAL on success. The user is in
			// edit context (fromEdit) so "quit" here means "leave
			// the edit", which commit already does.
			return m.commitEdit()
		}
		if hasDirtyDraft {
			m.flash("unsaved edit — :w to save or :q! to discard", false)
			return m, nil
		}
		return m, tea.Quit
	}
	switch args[0] {
	case "vault":
		if len(args) == 2 {
			m.scope = ipc.Scope{Vault: args[1]}
			return m.loadCurrentScope()
		}
	case "project":
		if len(args) == 2 {
			m.scope.Project = args[1]
			m.scope.Env = ""
			return m.loadCurrentScope()
		}
	case "env":
		if len(args) == 2 {
			m.scope.Env = args[1]
			return m.loadCurrentScope()
		}
	case "audit":
		m.Mode = ModeAudit
		return m, loadAuditCmd(m.client, m.scope.Vault, 200)
	case "reload":
		return m.loadCurrentScope()
	case "help":
		m.Mode = ModeHelp
		return m, nil
	}
	m.flash("unknown command: "+input, false)
	return m, nil
}

// ---- SEARCH mode --------------------------------------------------------

func (m Model) keySearch(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.cmdline == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc":
		if m.searchAudit {
			m.searchAudit = false // cancel: leave auditFilter unchanged
			m.cmdline = nil
			m.Mode = ModeAudit
			return m, nil
		}
		m.entriesFilter = ""
		m.cmdline = nil
		m.Mode = ModeNormal
		return m, nil
	case "enter":
		if m.searchAudit {
			m.auditFilter = m.cmdline.Input
			m.searchAudit = false
			m.cmdline = nil
			m.Mode = ModeAudit
			return m, nil
		}
		m.entriesFilter = m.cmdline.Input
		m.cmdline = nil
		m.Mode = ModeNormal
		m.entryCursor = 0
		return m, nil
	case "backspace":
		if len(m.cmdline.Input) > 0 {
			m.cmdline.Input = m.cmdline.Input[:len(m.cmdline.Input)-1]
		}
		return m, nil
	}
	if len(msg.Runes) > 0 {
		m.cmdline.Input += string(msg.Runes)
	}
	return m, nil
}

// ---- AUDIT mode ---------------------------------------------------------

func (m Model) keyAudit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Clear an active filter first; a second esc leaves the view.
		if m.auditFilter != "" {
			m.auditFilter = ""
			return m, nil
		}
		m.Mode = ModeNormal
		return m, nil
	case "q":
		m.Mode = ModeNormal
		return m, nil
	case "r":
		return m, loadAuditCmd(m.client, m.scope.Vault, 200)
	case "/":
		m.searchAudit = true
		m.Mode = ModeSearch
		m.cmdline = &cmdlineState{Prompt: "filter audit /", Input: m.auditFilter}
		return m, nil
	}
	return m, nil
}

// ---- HELP mode ----------------------------------------------------------

func (m Model) keyHelp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "?":
		m.Mode = ModeNormal
		return m, nil
	}
	return m, nil
}

// ---- AUTH REQUIRED mode -------------------------------------------------
//
// keyAuthRequired handles input for the "Authorize" password overlay.
// The user types their vault password (masked), presses Enter to retry the
// pending op, or Esc to cancel (original denial surfaced as a flash message).

func (m Model) keyAuthRequired(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	ar := m.authReq
	if ar == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	switch msg.String() {
	case "esc":
		// Cancel: clear overlay, flash the original denial reason.
		// Zero the put payload (a secret value) before releasing the reference.
		for i := range ar.value {
			ar.value[i] = 0
		}
		ar.value = ar.value[:0]
		m.Mode = ModeNormal
		m.authReq = nil
		m.flash("auth_required: "+ar.Cause, false)
		return m, nil
	case "ctrl+c":
		// Zero the put payload (a secret value) before quitting.
		for i := range ar.value {
			ar.value[i] = 0
		}
		ar.value = ar.value[:0]
		return m, tea.Quit
	case "enter":
		if len(ar.buf) == 0 {
			ar.retryErr = "password required"
			return m, nil
		}
		pw := []byte(string(ar.buf))
		// Zero the rune buffer; the byte slice pw is passed to the retry
		// command and zeroed there after c.Call.
		// Note: buffer zeroed; JSON marshaling copies are subject to GC.
		for i := range ar.buf {
			ar.buf[i] = 0
		}
		ar.buf = ar.buf[:0]
		ar.cur = 0
		ar.retryErr = ""
		// Issue the retry command.
		var cmd tea.Cmd
		switch ar.kind {
		case authRetryGet:
			cmd = authRetryGetCmd(m.client, ar.scope, ar.name, pw)
		case authRetryPut:
			if ar.createOnly {
				cmd = authRetryAddCmd(m.client, ar.scope, ar.name, ar.value, pw)
			} else {
				cmd = authRetryPutCmd(m.client, ar.scope, ar.name, ar.value, pw)
			}
		case authRetryDelete:
			cmd = authRetryDeleteCmd(m.client, ar.scope, ar.name, pw)
		case authRetryRename:
			cmd = authRetryRenameCmd(m.client, ar.scope, ar.name, ar.newName, pw)
		}
		return m, cmd
	case "backspace":
		if ar.cur > 0 {
			ar.buf = append(ar.buf[:ar.cur-1], ar.buf[ar.cur:]...)
			ar.cur--
		}
		return m, nil
	}
	// Plain rune input: append at cursor (no echo).
	if rs := msg.Runes; len(rs) > 0 {
		tail := append([]rune{}, ar.buf[ar.cur:]...)
		ar.buf = append(append(ar.buf[:ar.cur], rs...), tail...)
		ar.cur += len(rs)
	}
	return m, nil
}

// handleAuthRetry folds the result of an auth-step-up retry into the model.
// On success it replicates the success path of the original op; on failure it
// either shows the error inside the overlay (allowing re-entry) or transitions
// back to normal with a flash message.
func (m Model) handleAuthRetry(msg authRetryMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		// Wrong password or other retryable error: stay in the overlay.
		if m.authReq != nil {
			m.authReq.retryErr = msg.err.Error()
		}
		return m, nil
	}
	// Success: dismiss overlay.
	m.Mode = ModeNormal
	ar := m.authReq
	// Zero the put payload (authReqState.value invariant: must be cleared on
	// every exit from ModeAuthRequired, including successful submit).
	if ar != nil {
		for i := range ar.value {
			ar.value[i] = 0
		}
		ar.value = ar.value[:0]
	}
	m.authReq = nil

	switch msg.kind {
	case authRetryGet:
		// Resume the original get destination based on the mode that
		// initiated the op (recorded in ar.priorMode).
		switch {
		case ar != nil && ar.priorMode == ModeReveal:
			// Re-enter reveal with the value.
			m.Mode = ModeReveal
			m.reveal = &revealState{
				Name:      ar.name,
				Value:     string(msg.getResp.Value),
				ExpiresAt: time.Now().Add(7 * time.Second),
			}
		case ar != nil && ar.priorMode == ModeInsert && m.edit != nil && m.edit.Name == msg.name:
			// Prefill the insert buffer.
			m.edit.OriginalVal = string(msg.getResp.Value)
			m.edit.Value = m.edit.OriginalVal
			m.edit.CursorIdx = len(m.edit.Value)
			m.Mode = ModeInsert
		default:
			// Fallback: enter reveal.
			if ar != nil {
				m.Mode = ModeReveal
				m.reveal = &revealState{
					Name:      ar.name,
					Value:     string(msg.getResp.Value),
					ExpiresAt: time.Now().Add(7 * time.Second),
				}
			}
		}
		return m, nil
	case authRetryPut:
		m.flash("put "+msg.name+" ok", true)
	case authRetryDelete:
		m.flash("delete "+msg.name+" ok", true)
	case authRetryRename:
		m.flash("rename → "+msg.name+" ok", true)
	}
	return m, tea.Batch(
		loadEntriesCmd(m.client, m.scope),
		loadAuditCmd(m.client, m.scope.Vault, 10),
	)
}

// isAuthRequired reports whether err is a CodeAuthRequired response.
func (m Model) isAuthRequired(err error) bool {
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		return er.Code == ipc.CodeAuthRequired
	}
	return false
}

// authRequiredCause extracts the daemon's Message from a CodeAuthRequired
// error. Falls back to the full error string if the type assertion fails.
func authRequiredCause(err error) string {
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if er.Message != "" {
			return er.Message
		}
	}
	return err.Error()
}
