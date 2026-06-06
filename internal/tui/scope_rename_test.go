package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// recClient records the last write op while delegating reads to fakeClient.
type recClient struct {
	fakeClient
	lastOp  ipc.Op
	lastReq any
}

func (c *recClient) Call(op ipc.Op, req, resp any) error {
	c.lastOp = op
	c.lastReq = req
	return c.fakeClient.Call(op, req, resp)
}

func newRenameModel(t *testing.T, c Client) Model {
	t.Helper()
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := NewModel(c, "test", scope)
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = mAny.(Model)
	runQueue(t, &m, m.Init())
	m.Focus = FocusRail
	return m
}

func railIndex(m Model, kind railNodeKind, name string) int {
	for i, n := range m.railRows {
		if n.Kind != kind {
			continue
		}
		switch kind {
		case nodeVault:
			if n.Vault == name {
				return i
			}
		case nodeProject:
			if n.Project == name {
				return i
			}
		case nodeEnv:
			if n.Env == name {
				return i
			}
		}
	}
	return -1
}

func sendKey(m Model, k tea.KeyMsg) Model {
	mAny, _ := m.Update(k)
	return mAny.(Model)
}

func typeRunes(m Model, s string) Model {
	for _, r := range s {
		m = sendKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return m
}

func TestScopeRename_Vault(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	idx := railIndex(m, nodeVault, "work")
	if idx < 0 {
		t.Fatal("no 'work' vault node in rail")
	}
	m.railCursor = idx

	m = sendKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if m.Mode != ModeScopeRename || m.scopeRename == nil || m.scopeRename.old != "work" {
		t.Fatalf("did not enter scope rename for work: mode=%v sr=%v", m.Mode, m.scopeRename)
	}
	for range "work" {
		m = sendKey(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = typeRunes(m, "renamed")
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if m.Mode != ModeNormal {
		t.Fatalf("mode after enter = %v, want NORMAL", m.Mode)
	}
	if cmd == nil {
		t.Fatal("expected a rename command")
	}
	_ = cmd()
	if c.lastOp != ipc.OpVaultRename {
		t.Fatalf("op = %v, want vault.rename", c.lastOp)
	}
	req := c.lastReq.(ipc.VaultRenameReq)
	if req.OldName != "work" || req.NewName != "renamed" {
		t.Fatalf("got (%q→%q), want (work→renamed)", req.OldName, req.NewName)
	}
}

func TestScopeRename_Project(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	idx := railIndex(m, nodeProject, "billing")
	if idx < 0 {
		t.Fatal("no 'billing' project node in rail")
	}
	m.railCursor = idx

	m = sendKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if m.Mode != ModeScopeRename || m.scopeRename == nil || m.scopeRename.old != "billing" {
		t.Fatalf("did not enter project rename: mode=%v", m.Mode)
	}
	for range "billing" {
		m = sendKey(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = typeRunes(m, "invoicing")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected a rename command")
	}
	_ = cmd()
	if c.lastOp != ipc.OpProjectRename {
		t.Fatalf("op = %v, want project.rename", c.lastOp)
	}
	req := c.lastReq.(ipc.ProjectRenameReq)
	if req.OldName != "billing" || req.NewName != "invoicing" {
		t.Fatalf("got (%q→%q), want (billing→invoicing)", req.OldName, req.NewName)
	}
}

func TestScopeRename_RefusesDefaultVault(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	idx := railIndex(m, nodeVault, "default")
	if idx < 0 {
		t.Fatal("no default vault node")
	}
	m.railCursor = idx
	m = sendKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if m.Mode == ModeScopeRename {
		t.Fatal("entered rename for the default vault — should be refused")
	}
}

func key(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func TestScopeDelete_Project(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	m.railCursor = railIndex(m, nodeProject, "billing")

	m = sendKey(m, key('d'))
	m = sendKey(m, key('d'))
	if m.Mode != ModeConfirmDelete || m.confirm == nil || !m.confirm.Scope {
		t.Fatalf("not in scope confirm: mode=%v confirm=%+v", m.Mode, m.confirm)
	}
	if m.confirm.Kind != nodeProject || m.confirm.Name != "billing" {
		t.Fatalf("confirm = %+v", m.confirm)
	}
	mAny, cmd := m.Update(key('d'))
	m = mAny.(Model)
	if m.Mode != ModeNormal {
		t.Fatalf("mode after confirm = %v", m.Mode)
	}
	if cmd == nil {
		t.Fatal("expected a delete command")
	}
	_ = cmd()
	if c.lastOp != ipc.OpProjectDelete {
		t.Fatalf("op = %v, want project.delete", c.lastOp)
	}
}

func TestScopeDelete_RefusesDefaultProject(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	m.railCursor = railIndex(m, nodeProject, "default")
	m = sendKey(m, key('d'))
	m = sendKey(m, key('d'))
	if m.Mode == ModeConfirmDelete {
		t.Fatal("entered confirm for the default project — should be refused")
	}
}

func TestScopeDelete_EscCancels(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	m.railCursor = railIndex(m, nodeProject, "billing")
	m = sendKey(m, key('d'))
	m = sendKey(m, key('d'))
	m = sendKey(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.Mode != ModeNormal || m.confirm != nil {
		t.Fatalf("ESC did not cancel scope confirm: mode=%v confirm=%v", m.Mode, m.confirm)
	}
}

func TestScopeRename_EscCancels(t *testing.T) {
	c := &recClient{}
	m := newRenameModel(t, c)
	idx := railIndex(m, nodeVault, "work")
	m.railCursor = idx
	m = sendKey(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = typeRunes(m, "xyz")
	m = sendKey(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.Mode != ModeNormal || m.scopeRename != nil {
		t.Fatalf("ESC did not cancel rename: mode=%v sr=%v", m.Mode, m.scopeRename)
	}
}
