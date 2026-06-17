package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// fakeClient stubs the Client interface with a fixed dataset so we
// can render deterministic frames at each tier.
type fakeClient struct{}

// fakeNow is a FIXED timestamp used everywhere fakeClient needs a time, so the
// rendered snapshots written to testdata/ are deterministic — previously the
// status LastActive and the RECENT AUDIT events used time.Now(), which made the
// committed snapshots churn (a dirty tree) on every test run.
var fakeNow = time.Date(2026, 6, 2, 8, 41, 0, 0, time.UTC)

func (fakeClient) Call(op ipc.Op, req any, resp any) error {
	switch op {
	case ipc.OpStatus:
		if r, ok := resp.(*ipc.StatusResp); ok {
			now := fakeNow
			*r = ipc.StatusResp{
				Vaults: []ipc.VaultSummary{
					{Name: "default", Initialized: true, Locked: false, LastActive: &now},
					{Name: "work", Initialized: true, Locked: false},
				},
			}
		}
	case ipc.OpProjectList:
		if r, ok := resp.(*ipc.ProjectListResp); ok {
			*r = ipc.ProjectListResp{
				Projects: []ipc.ProjectInfo{
					{Name: "billing"},
					{Name: "default"},
				},
			}
		}
	case ipc.OpEnvList:
		if r, ok := resp.(*ipc.EnvListResp); ok {
			*r = ipc.EnvListResp{
				Envs: []ipc.EnvInfo{
					{Name: "default", IsDefault: true},
					{Name: "staging"},
				},
			}
		}
	case ipc.OpList:
		if r, ok := resp.(*ipc.ListResp); ok {
			now := fakeNow
			*r = ipc.ListResp{
				Secrets: []ipc.SecretMeta{
					{Name: "API_KEY", Source: "scope", CreatedAt: now, UpdatedAt: now},
					{Name: "DB_URL", Source: "scope", CreatedAt: now, UpdatedAt: now},
					{Name: "STRIPE_SK", Source: "scope", CreatedAt: now, UpdatedAt: now},
				},
			}
		}
	case ipc.OpAuditTail:
		if r, ok := resp.(*ipc.AuditTailResp); ok {
			*r = ipc.AuditTailResp{
				Events: []ipc.AuditEvent{
					{Op: "put", EntryName: "STRIPE_SK", Outcome: "ok", TS: fakeNow.UnixNano()},
					{Op: "get", EntryName: "DB_URL", Outcome: "ok", TS: fakeNow.UnixNano()},
				},
			}
		}
	}
	return nil
}

// driveTo runs the model through Init + the given window size, then
// processes any commands until quiescent. Returns the model and the
// final View.
func driveTo(t *testing.T, width, height int) (Model, string) {
	t.Helper()
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	model := NewModel(fakeClient{}, "test", scope)
	// Seed with WindowSize.
	mAny, _ := model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m := mAny.(Model)

	// Drive Init's batched commands synchronously.
	cmd := m.Init()
	runQueue(t, &m, cmd)

	return m, m.View()
}

// runQueue runs cmds until none remain — sufficient for our IPC stubs.
func runQueue(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	// Reasonable upper bound — we shouldn't recurse more than a
	// handful of times for the seeded fake.
	for i := 0; cmd != nil && i < 200; i++ {
		msg := cmd()
		if msg == nil {
			return
		}
		// Skip ticks so we don't loop forever.
		if _, isTick := msg.(tickMsg); isTick {
			return
		}
		// Batch messages produce multiple sub-cmds.
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, c := range batch {
				runQueue(t, m, c)
			}
			return
		}
		mAny, next := m.Update(msg)
		*m = mAny.(Model)
		cmd = next
	}
}

func TestRender_Standard_NormalMode(t *testing.T) {
	_, view := driveTo(t, 100, 30)
	wantContains := []string{
		"BYN",
		"default", "billing", "staging",
		"ENV-VARS",
		"API_KEY",
		"DB_URL",
		"STRIPE_SK",
		"NORMAL",
	}
	for _, s := range wantContains {
		if !strings.Contains(view, s) {
			t.Errorf("standard view missing %q in:\n%s", s, view)
		}
	}
}

func TestRender_Tiny_NoRail(t *testing.T) {
	_, view := driveTo(t, 50, 24)
	if !strings.Contains(view, "default") {
		t.Errorf("tiny view missing breadcrumb 'default':\n%s", view)
	}
	// In tiny mode the rail is hidden — the literal app header "BYN"
	// from the rail must NOT appear.
	if strings.Contains(view, "BYN") {
		t.Errorf("tiny view should hide the rail header, got:\n%s", view)
	}
}

func TestRender_Medium_HasRail(t *testing.T) {
	_, view := driveTo(t, 75, 28)
	if !strings.Contains(view, "BYN") {
		t.Errorf("medium view should show rail header 'BYN':\n%s", view)
	}
	if !strings.Contains(view, "ENV-VARS") {
		t.Errorf("medium view missing ENV-VARS:\n%s", view)
	}
}

func TestRender_Large_HasDetailPane(t *testing.T) {
	_, view := driveTo(t, 140, 35)
	// Large tier shows detail pane. With no entry selected (entry
	// cursor at 0 but content focus), we expect the title to be the
	// selected entry's name OR a placeholder. Either way it sits to
	// the right of the content.
	if !strings.Contains(view, "Created") {
		t.Errorf("large view detail pane should show 'Created' metadata field:\n%s", view)
	}
}

func TestRender_BelowMin_Fallback(t *testing.T) {
	_, view := driveTo(t, 30, 10)
	if !strings.Contains(view, "Terminal too small") {
		t.Errorf("below-min view should say 'Terminal too small':\n%s", view)
	}
}

func TestRender_ResizeAcrossTiers(t *testing.T) {
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := NewModel(fakeClient{}, "test", scope)
	for _, sz := range []struct{ w, h int }{
		{50, 20},  // Tiny
		{75, 24},  // Medium
		{100, 30}, // Standard
		{140, 35}, // Large
		{50, 20},  // Back to Tiny
	} {
		mAny, _ := m.Update(tea.WindowSizeMsg{Width: sz.w, Height: sz.h})
		m = mAny.(Model)
		view := m.View()
		if view == "" {
			t.Errorf("empty view at %dx%d", sz.w, sz.h)
		}
	}
}
