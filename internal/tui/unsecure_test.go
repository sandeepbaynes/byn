package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// unsecureClient is fakeClient with its first listed entry stored unsecure,
// recording every call so a test can see what the TUI asked the daemon for.
type unsecureClient struct {
	calls []struct {
		op  ipc.Op
		req any
	}
}

func (c *unsecureClient) Call(op ipc.Op, req, resp any) error {
	c.calls = append(c.calls, struct {
		op  ipc.Op
		req any
	}{op, req})
	if err := (fakeClient{}).Call(op, req, resp); err != nil {
		return err
	}
	if r, ok := resp.(*ipc.ListResp); ok && len(r.Secrets) > 0 {
		r.Secrets[0].Unsecure = true
	}
	return nil
}

func (c *unsecureClient) last(op ipc.Op) any {
	for i := len(c.calls) - 1; i >= 0; i-- {
		if c.calls[i].op == op {
			return c.calls[i].req
		}
	}
	return nil
}

// runCmd feeds a command's message back into the model, once.
func runCmd(m Model, cmd tea.Cmd) Model {
	if cmd == nil {
		return m
	}
	mAny, _ := m.Update(cmd())
	return mAny.(Model)
}

func command(m Model, text string) (Model, tea.Cmd) {
	mAny, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	m = typeRunes(mAny.(Model), text)
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	return mAny.(Model), cmd
}

// The row says so in place of the mask, and the detail pane says what it means.
func TestUnsecure_RowAndDetailSayIt(t *testing.T) {
	m := setupAuthModel(t, &unsecureClient{})
	first, second := m.entries[0], m.entries[1]
	if row := m.renderEntryRow(first, false, false, 80); !strings.Contains(row, "◌ unsecure") || strings.Contains(row, "●") {
		t.Fatalf("unsecure row = %q, want the tag and no mask", row)
	}
	if row := m.renderEntryRow(second, false, false, 80); strings.Contains(row, "◌") || !strings.Contains(row, "●") {
		t.Fatalf("sealed row = %q, want a mask and no tag", row)
	}
	// The detail pane is drawn on wide terminals only.
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 170, Height: 40})
	if view := mAny.(Model).View(); !strings.Contains(view, "no password needed") {
		t.Fatalf("detail pane does not explain the unsecure entry:\n%s", view)
	}
}

// Saving an edit of an unsecure entry keeps it unsecure: the row above the box
// says what it is. `:w secure` seals it instead.
func TestUnsecure_EditKeepsItUnlessToldOtherwise(t *testing.T) {
	for _, tc := range []struct {
		save string
		want bool
	}{{"w", true}, {"w secure", false}} {
		c := &unsecureClient{}
		m := setupAuthModel(t, c)
		mAny, cmd := m.Update(key('i'))
		m = runCmd(mAny.(Model), cmd)
		if m.edit == nil || !m.edit.Unsecure {
			t.Fatalf("%s: edit buffer = %+v, want Unsecure", tc.save, m.edit)
		}
		if !strings.Contains(m.renderEditBox(80), ":w secure seals it") {
			t.Fatalf("%s: the edit box does not say the value is unsecure", tc.save)
		}
		m = typeRunes(m, "x")
		m.Mode = ModeInsert
		m, cmd = command(m, tc.save)
		m = runCmd(m, cmd)
		req, ok := c.last(ipc.OpPut).(ipc.PutReq)
		if !ok {
			t.Fatalf("%s: no put was sent", tc.save)
		}
		if req.Unsecure != tc.want {
			t.Fatalf(":%s sent Unsecure=%v, want %v", tc.save, req.Unsecure, tc.want)
		}
	}
}

// A sealed entry stays sealed on save, and `:w unsecure` is how it is opened
// while writing a new value.
func TestUnsecure_EditOfSealedEntry(t *testing.T) {
	for _, tc := range []struct {
		save string
		want bool
	}{{"w", false}, {"w unsecure", true}} {
		c := &unsecureClient{}
		m := setupAuthModel(t, c)
		mAny, _ := m.Update(key('j'))
		mAny, cmd := mAny.(Model).Update(key('i'))
		m = runCmd(mAny.(Model), cmd)
		if m.edit == nil || m.edit.Unsecure {
			t.Fatalf("%s: edit buffer = %+v, want sealed", tc.save, m.edit)
		}
		m = typeRunes(m, "x")
		m.Mode = ModeInsert
		m, cmd = command(m, tc.save)
		runCmd(m, cmd)
		req, ok := c.last(ipc.OpPut).(ipc.PutReq)
		if !ok {
			t.Fatalf("%s: no put was sent", tc.save)
		}
		if req.Unsecure != tc.want {
			t.Fatalf(":%s sent Unsecure=%v, want %v", tc.save, req.Unsecure, tc.want)
		}
	}
}

// :unsecure asks for the password before anything is sent — the daemon would
// refuse without one, session or not — and sends it with the request.
func TestUnsecure_CommandAsksForThePassword(t *testing.T) {
	c := &unsecureClient{}
	m := setupAuthModel(t, c)
	mAny, _ := m.Update(key('j')) // a sealed entry
	m, cmd := command(mAny.(Model), "unsecure")
	if cmd != nil || m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v cmd=%v, want the password overlay and nothing sent", m.Mode, cmd != nil)
	}
	if c.last(ipc.OpSecureSet) != nil {
		t.Fatal("secure.set was sent before a password was typed")
	}
	m = typeRunes(m, "pw123")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = runCmd(mAny.(Model), cmd)
	req, ok := c.last(ipc.OpSecureSet).(ipc.SecureSetReq)
	if !ok {
		t.Fatal("secure.set was not sent")
	}
	if req.Secure || string(req.Password) != "pw123" || len(req.Names) != 1 || req.Names[0] != m.entries[1].Name {
		t.Fatalf("secure.set = %+v", req)
	}
	if m.Mode != ModeNormal {
		t.Fatalf("mode after success = %v, want normal", m.Mode)
	}
}

// :secure goes straight through; it is an ordinary update.
func TestUnsecure_SecureCommand(t *testing.T) {
	c := &unsecureClient{}
	m := setupAuthModel(t, c)
	m, cmd := command(m, "secure")
	if cmd == nil {
		t.Fatalf("nothing sent; status: %q", m.View())
	}
	runCmd(m, cmd)
	req, ok := c.last(ipc.OpSecureSet).(ipc.SecureSetReq)
	if !ok || !req.Secure || len(req.Password) != 0 {
		t.Fatalf("secure.set = %+v ok=%v", req, ok)
	}
	// And asking for the state it already has sends nothing.
	c2 := &unsecureClient{}
	m2 := setupAuthModel(t, c2)
	if _, cmd := command(m2, "unsecure"); cmd != nil || c2.last(ipc.OpSecureSet) != nil {
		t.Fatal(":unsecure on an unsecure entry sent a request")
	}
}
