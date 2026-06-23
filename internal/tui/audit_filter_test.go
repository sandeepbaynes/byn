package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func tuiKey(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func asModel(t *testing.T, anyM tea.Model) Model {
	t.Helper()
	mm, ok := anyM.(Model)
	if !ok {
		t.Fatal("expected a Model")
	}
	return mm
}

func TestAuditMatches(t *testing.T) {
	e := ipc.AuditEvent{Op: "get", Outcome: "ok", BynPath: "/proj/.byn",
		Project: "alpha", Env: "prod", CallerComm: "byn", CallerUID: 501}
	for _, term := range []string{"get", "alpha", "prod", ".byn", "byn", "uid=501", "ALPHA"} {
		if !auditMatches(e, term) {
			t.Errorf("auditMatches should match %q", term)
		}
	}
	for _, term := range []string{"put", "beta", "uid=999"} {
		if auditMatches(e, term) {
			t.Errorf("auditMatches should NOT match %q", term)
		}
	}
}

// TestAuditFilterFlow drives "/" → type → enter → esc through the audit view.
func TestAuditFilterFlow(t *testing.T) {
	m := Model{Mode: ModeAudit}
	// "/" starts an audit-targeted search (not the entry search).
	mAny, _ := m.keyAudit(tuiKey("/"))
	m = asModel(t, mAny)
	if m.Mode != ModeSearch || !m.searchAudit || m.cmdline == nil {
		t.Fatalf("/ in audit: mode=%v searchAudit=%v cmdline=%v", m.Mode, m.searchAudit, m.cmdline)
	}
	// Commit a term → auditFilter set, back to ModeAudit, entriesFilter untouched.
	m.cmdline.Input = "denied"
	mAny, _ = m.keySearch(tuiKey("enter"))
	m = asModel(t, mAny)
	if m.Mode != ModeAudit || m.auditFilter != "denied" || m.searchAudit || m.entriesFilter != "" {
		t.Fatalf("after enter: mode=%v filter=%q searchAudit=%v entries=%q",
			m.Mode, m.auditFilter, m.searchAudit, m.entriesFilter)
	}
	// First esc clears the filter (stays in audit); second esc exits.
	mAny, _ = m.keyAudit(tuiKey("esc"))
	m = asModel(t, mAny)
	if m.auditFilter != "" || m.Mode != ModeAudit {
		t.Fatalf("first esc should clear filter + stay: filter=%q mode=%v", m.auditFilter, m.Mode)
	}
	mAny, _ = m.keyAudit(tuiKey("esc"))
	m = asModel(t, mAny)
	if m.Mode != ModeNormal {
		t.Fatalf("second esc should exit audit: mode=%v", m.Mode)
	}
}

// TestAuditPageNav drives the older/newest page keys and the stable cursor.
func TestAuditPageNav(t *testing.T) {
	m := Model{Mode: ModeAudit, auditMore: true, audit: []ipc.AuditEvent{{Index: 90}, {Index: 99}}}
	// "]" older → freeze on the smallest #N shown (#90), dispatch a load.
	mAny, cmd := m.keyAudit(tuiKey("]"))
	m = asModel(t, mAny)
	if m.auditBefore != 90 || cmd == nil {
		t.Fatalf("] should freeze auditBefore at 90 and load, got before=%d cmd=%v", m.auditBefore, cmd != nil)
	}
	// "[" → back to live newest (cursor 0).
	mAny, cmd = m.keyAudit(tuiKey("["))
	m = asModel(t, mAny)
	if m.auditBefore != 0 || cmd == nil {
		t.Fatalf("[ should return to live (0) and reload, got before=%d cmd=%v", m.auditBefore, cmd != nil)
	}
	// "]" with no older events must not freeze.
	noOlder := Model{Mode: ModeAudit, auditMore: false, audit: []ipc.AuditEvent{{Index: 0}}}
	mAny, _ = noOlder.keyAudit(tuiKey("]"))
	if asModel(t, mAny).auditBefore != 0 {
		t.Fatal("] with no older events must stay live")
	}
}
