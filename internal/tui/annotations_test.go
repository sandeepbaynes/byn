package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// annFake is a daemon for the annotations view: it keeps a description and a
// list of notes, records every annotation request, and can demand a password.
type annFake struct {
	desc     *ipc.AnnotationView
	notes    []ipc.AnnotationView
	password string // when set, notes and writes need it
	nextID   int64
	history  []ipc.AnnotationVersionView
	meta     ipc.SecretMeta

	reqs []any
}

func newAnnFake() *annFake {
	t := fakeNow
	return &annFake{
		desc:   &ipc.AnnotationView{ID: 1, Kind: "description", Body: "staging Stripe key", Author: "owner", CreatedAt: t, UpdatedAt: t},
		notes:  []ipc.AnnotationView{{ID: 2, Kind: "note", Body: "account 1234", Author: "agent", AuthorComm: "node", CreatedAt: t, UpdatedAt: t.Add(time.Hour)}},
		nextID: 10,
		meta:   ipc.SecretMeta{Name: "API_KEY", Source: "scope", Description: "staging Stripe key", Notes: 1, CreatedAt: t, UpdatedAt: t},
	}
}

func (f *annFake) authed(pw []byte) bool { return f.password == "" || string(pw) == f.password }

func authErr() error {
	return &ipc.ErrResponse{Code: ipc.CodeAuthRequired, Message: "authorization required"}
}

func (f *annFake) Call(op ipc.Op, req, resp any) error {
	switch op {
	case ipc.OpList:
		r := resp.(*ipc.ListResp)
		*r = ipc.ListResp{Secrets: []ipc.SecretMeta{f.meta}}
		return nil
	case ipc.OpAnnotationList:
		q := req.(ipc.AnnotationListReq)
		f.reqs = append(f.reqs, q)
		r := resp.(*ipc.AnnotationListResp)
		out := ipc.AnnotationListResp{}
		if f.desc != nil {
			out.Descriptions = []ipc.AnnotationView{*f.desc}
		}
		live := 0
		for _, n := range f.notes {
			if n.RemovedAt == nil {
				live++
			}
		}
		out.NoteCount = live
		if !f.authed(q.Password) {
			out.NotesWithheld = live > 0
			*r = out
			return nil
		}
		for _, n := range f.notes {
			if n.RemovedAt == nil || q.IncludeRemoved {
				out.Notes = append(out.Notes, n)
			}
		}
		*r = out
		return nil
	case ipc.OpAnnotationAdd:
		q := req.(ipc.AnnotationAddReq)
		f.reqs = append(f.reqs, q)
		if !f.authed(q.Password) {
			return authErr()
		}
		f.nextID++
		f.notes = append(f.notes, ipc.AnnotationView{ID: f.nextID, Kind: "note", Body: q.Text, Author: "owner", CreatedAt: fakeNow, UpdatedAt: fakeNow})
		return nil
	case ipc.OpAnnotationEdit:
		q := req.(ipc.AnnotationEditReq)
		f.reqs = append(f.reqs, q)
		if !f.authed(q.Password) {
			return authErr()
		}
		for i := range f.notes {
			if f.notes[i].ID == q.ID {
				f.notes[i].Body = q.Text
			}
		}
		return nil
	case ipc.OpAnnotationRemove:
		q := req.(ipc.AnnotationRemoveReq)
		f.reqs = append(f.reqs, q)
		if !f.authed(q.Password) {
			return authErr()
		}
		for i := range f.notes {
			if f.notes[i].ID == q.ID {
				t := fakeNow
				f.notes[i].RemovedAt = &t
			}
		}
		return nil
	case ipc.OpAnnotationSet:
		q := req.(ipc.AnnotationSetReq)
		f.reqs = append(f.reqs, q)
		if !f.authed(q.Password) {
			return authErr()
		}
		if q.Clear {
			f.desc = nil
		} else {
			f.desc = &ipc.AnnotationView{ID: 1, Kind: "description", Body: q.Text, Author: "owner", CreatedAt: fakeNow, UpdatedAt: fakeNow}
		}
		return nil
	case ipc.OpAnnotationHistory:
		q := req.(ipc.AnnotationHistoryReq)
		f.reqs = append(f.reqs, q)
		if !f.authed(q.Password) {
			return authErr()
		}
		resp.(*ipc.AnnotationHistoryResp).Versions = f.history
		return nil
	}
	return fakeClient{}.Call(op, req, resp)
}

// lastReq returns the most recent recorded request of type T.
func lastReq[T any](f *annFake) (T, bool) {
	for i := len(f.reqs) - 1; i >= 0; i-- {
		if r, ok := f.reqs[i].(T); ok {
			return r, true
		}
	}
	var zero T
	return zero, false
}

func annModel(t *testing.T, f *annFake) Model {
	t.Helper()
	m := NewModel(f, "test", ipc.Scope{Vault: "default", Project: "default", Env: "default"})
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = mAny.(Model)
	runQueue(t, &m, m.Init())
	m.Focus = FocusContent
	return m
}

func press(t *testing.T, m *Model, keys ...string) {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "backspace":
			msg = tea.KeyMsg{Type: tea.KeyBackspace}
		case "ctrl+u":
			msg = tea.KeyMsg{Type: tea.KeyCtrlU}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		mAny, cmd := m.Update(msg)
		*m = mAny.(Model)
		runQueue(t, m, cmd)
	}
}

func typeText(t *testing.T, m *Model, s string) {
	t.Helper()
	for _, r := range s {
		press(t, m, string(r))
	}
}

// ---- the list ---------------------------------------------------------------

func TestEntryRow_ShowsDescriptionAndNoteCount(t *testing.T) {
	m := annModel(t, newAnnFake())
	out := m.View()
	if !strings.Contains(out, "staging Stripe key") {
		t.Fatalf("list does not show the description:\n%s", out)
	}
	if !strings.Contains(out, "✎1") {
		t.Fatalf("list does not show the note count:\n%s", out)
	}
	if strings.Contains(out, "account 1234") {
		t.Fatal("a note's text leaked into the list")
	}
}

// A description too long for the row is cut to fit, never wrapped into the
// next row or pushed past the date.
func TestEntryRow_LongDescriptionIsCut(t *testing.T) {
	f := newAnnFake()
	f.meta.Description = strings.Repeat("very long words ", 30)
	m := annModel(t, f)
	for _, ln := range strings.Split(m.renderContent(), "\n") {
		if strings.Contains(ln, "API_KEY") && !strings.Contains(ln, "…") {
			t.Fatalf("long description not ellipsized: %q", ln)
		}
	}
}

// ---- the view -----------------------------------------------------------------

func TestAnnotations_OpenShowsDescriptionNotesAndWho(t *testing.T) {
	f := newAnnFake()
	m := annModel(t, f)
	press(t, &m, "n")
	if m.Mode != ModeAnnotations {
		t.Fatalf("mode = %v, want NOTES", m.Mode)
	}
	out := m.View()
	for _, want := range []string{"staging Stripe key", "account 1234", "by agent node", "edited", "by you"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q:\n%s", want, out)
		}
	}
	press(t, &m, "esc")
	if m.Mode != ModeNormal || m.ann != nil {
		t.Fatalf("esc: mode = %v, ann = %v", m.Mode, m.ann)
	}
}

func TestAnnotations_OpenNeedsAnEntry(t *testing.T) {
	m := annModel(t, newAnnFake())
	m.Focus = FocusRail
	press(t, &m, "n")
	if m.Mode != ModeNormal {
		t.Fatalf("mode = %v, want NORMAL from the rail", m.Mode)
	}
}

func TestAnnotations_AddEditRemove(t *testing.T) {
	f := newAnnFake()
	m := annModel(t, f)
	press(t, &m, "n")

	// Add.
	press(t, &m, "a")
	typeText(t, &m, "rotated in May")
	press(t, &m, "enter")
	add, ok := lastReq[ipc.AnnotationAddReq](f)
	if !ok || add.Text != "rotated in May" || add.Target.Name != "API_KEY" {
		t.Fatalf("add = %+v", add)
	}
	if !strings.Contains(m.View(), "rotated in May") {
		t.Fatal("added note not shown after reload")
	}

	// Edit the first note.
	press(t, &m, "j", "e", "ctrl+u")
	typeText(t, &m, "account 5678")
	press(t, &m, "enter")
	ed, ok := lastReq[ipc.AnnotationEditReq](f)
	if !ok || ed.ID != 2 || ed.Text != "account 5678" {
		t.Fatalf("edit = %+v", ed)
	}

	// Remove asks first; anything but y keeps it.
	press(t, &m, "d", "n")
	if _, ok := lastReq[ipc.AnnotationRemoveReq](f); ok {
		t.Fatal("removed without confirmation")
	}
	press(t, &m, "d")
	if !strings.Contains(m.View(), "remove this note?") {
		t.Fatal("no confirm prompt")
	}
	press(t, &m, "y")
	rm, ok := lastReq[ipc.AnnotationRemoveReq](f)
	if !ok || rm.ID != 2 {
		t.Fatalf("remove = %+v", rm)
	}
	if strings.Contains(m.View(), "account 5678") {
		t.Fatal("removed note still listed")
	}
}

func TestAnnotations_EscCancelsTyping(t *testing.T) {
	f := newAnnFake()
	m := annModel(t, f)
	press(t, &m, "n", "a")
	typeText(t, &m, "draft")
	press(t, &m, "esc")
	if m.Mode != ModeAnnotations || m.ann.Typing != annTypingNone {
		t.Fatalf("esc while typing: mode %v typing %v", m.Mode, m.ann.Typing)
	}
	if _, ok := lastReq[ipc.AnnotationAddReq](f); ok {
		t.Fatal("cancelled note was sent")
	}
	// Unchanged edits send nothing either.
	press(t, &m, "e", "enter")
	if _, ok := lastReq[ipc.AnnotationSetReq](f); ok {
		t.Fatal("an unchanged description was re-sent")
	}
}

func TestAnnotations_DescribeAndClear(t *testing.T) {
	f := newAnnFake()
	m := annModel(t, f)
	press(t, &m, "n", "e", "ctrl+u")
	typeText(t, &m, "prod key")
	press(t, &m, "enter")
	set, ok := lastReq[ipc.AnnotationSetReq](f)
	if !ok || set.Text != "prod key" || set.Clear {
		t.Fatalf("describe = %+v", set)
	}
	press(t, &m, "d", "y")
	set, _ = lastReq[ipc.AnnotationSetReq](f)
	if !set.Clear {
		t.Fatalf("clear = %+v", set)
	}
	if !strings.Contains(m.View(), "(none — e to write one)") {
		t.Fatal("cleared description still shown")
	}
}

func TestAnnotations_HistoryShowsWhoDidWhat(t *testing.T) {
	f := newAnnFake()
	f.history = []ipc.AnnotationVersionView{
		{VersionNo: 1, Op: "create", Body: "acct 12", Author: "agent", AuthorComm: "node", CreatedAt: fakeNow},
		{VersionNo: 2, Op: "edit", Body: "account 1234", Author: "owner", CreatedAt: fakeNow},
		{VersionNo: 3, Op: "delete", Author: "owner", CreatedAt: fakeNow},
	}
	m := annModel(t, f)
	press(t, &m, "n", "j", "h")
	h, ok := lastReq[ipc.AnnotationHistoryReq](f)
	if !ok || h.ID != 2 {
		t.Fatalf("history req = %+v", h)
	}
	out := m.View()
	for _, want := range []string{"v1 · added by agent node", "acct 12", "v2 · edited by you", "v3 · removed by you"} {
		if !strings.Contains(out, want) {
			t.Errorf("history missing %q:\n%s", want, out)
		}
	}
	press(t, &m, "h")
	if strings.Contains(m.View(), "v1 · added") {
		t.Fatal("h did not close the history")
	}
}

func TestAnnotations_ShowRemoved(t *testing.T) {
	f := newAnnFake()
	gone := fakeNow
	f.notes = append(f.notes, ipc.AnnotationView{ID: 3, Kind: "note", Body: "old acct", Author: "owner", CreatedAt: fakeNow, UpdatedAt: fakeNow, RemovedAt: &gone})
	m := annModel(t, f)
	press(t, &m, "n")
	if strings.Contains(m.View(), "old acct") {
		t.Fatal("removed note shown without asking")
	}
	press(t, &m, "r")
	q, _ := lastReq[ipc.AnnotationListReq](f)
	if !q.IncludeRemoved {
		t.Fatal("r did not ask for removed notes")
	}
	out := m.View()
	if !strings.Contains(out, "old acct") || !strings.Contains(out, "REMOVED") {
		t.Fatalf("removed note not listed:\n%s", out)
	}
	// A removed note has history but no edit.
	press(t, &m, "j", "j", "e")
	if m.ann.Typing != annTypingNone {
		t.Fatal("a removed note opened for editing")
	}
}

// An inherited row's notes are default's: the view reads and writes there.
func TestAnnotations_InheritedUsesDefault(t *testing.T) {
	f := newAnnFake()
	f.meta.Source = "default"
	m := NewModel(f, "test", ipc.Scope{Vault: "default", Project: "default", Env: "prod"})
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
	m = mAny.(Model)
	runQueue(t, &m, m.Init())
	m.Focus = FocusContent
	press(t, &m, "n")
	q, _ := lastReq[ipc.AnnotationListReq](f)
	if q.Scope.Env != "default" {
		t.Fatalf("read from env %q, want default", q.Scope.Env)
	}
	if !strings.Contains(m.View(), "inherited from default") {
		t.Fatal("view does not say the notes are default's")
	}
}

// ---- passwords --------------------------------------------------------------

func TestAnnotations_WithheldThenPassword(t *testing.T) {
	f := newAnnFake()
	f.password = "hunter2"
	m := annModel(t, f)
	press(t, &m, "n")
	if !strings.Contains(m.View(), "p to enter the master password") {
		t.Fatalf("withheld notes not explained:\n%s", m.View())
	}
	press(t, &m, "p")
	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want the password prompt", m.Mode)
	}
	// A wrong password keeps the prompt up.
	typeText(t, &m, "nope")
	press(t, &m, "enter")
	if m.Mode != ModeAuthRequired || m.authReq == nil || m.authReq.retryErr == "" {
		t.Fatalf("wrong password: mode %v", m.Mode)
	}
	typeText(t, &m, "hunter2")
	press(t, &m, "enter")
	if m.Mode != ModeAnnotations || !strings.Contains(m.View(), "account 1234") {
		t.Fatalf("after password: mode %v\n%s", m.Mode, m.View())
	}
	// The password is reused for the rest of the view: no second prompt.
	press(t, &m, "a")
	typeText(t, &m, "second")
	press(t, &m, "enter")
	if m.Mode != ModeAnnotations {
		t.Fatalf("asked again: mode %v", m.Mode)
	}
	add, _ := lastReq[ipc.AnnotationAddReq](f)
	if string(add.Password) != "hunter2" {
		t.Fatalf("add password = %q", add.Password)
	}
	// Closing forgets it.
	pw := m.ann.pw
	press(t, &m, "esc")
	for _, b := range pw {
		if b != 0 {
			t.Fatal("password not zeroed on close")
		}
	}
}

func TestAnnotations_WriteAsksForPasswordAndReplays(t *testing.T) {
	f := newAnnFake()
	m := annModel(t, f)
	press(t, &m, "n")
	f.password = "hunter2" // the session lapses after the read
	press(t, &m, "a")
	typeText(t, &m, "late note")
	press(t, &m, "enter")
	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want the password prompt", m.Mode)
	}
	// Esc returns to the notes view, not the list.
	press(t, &m, "esc")
	if m.Mode != ModeAnnotations {
		t.Fatalf("esc from prompt: mode = %v", m.Mode)
	}
	press(t, &m, "a")
	typeText(t, &m, "late note")
	press(t, &m, "enter")
	typeText(t, &m, "hunter2")
	press(t, &m, "enter")
	if m.Mode != ModeAnnotations || !strings.Contains(m.View(), "late note") {
		t.Fatalf("replay failed: mode %v\n%s", m.Mode, m.View())
	}
}

func TestAnnotations_HistoryAsksForPassword(t *testing.T) {
	f := newAnnFake()
	f.history = []ipc.AnnotationVersionView{{VersionNo: 1, Op: "create", Body: "account 1234", Author: "owner", CreatedAt: fakeNow}}
	m := annModel(t, f)
	press(t, &m, "n")
	f.password = "pw"
	press(t, &m, "j", "h")
	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want the password prompt", m.Mode)
	}
	typeText(t, &m, "pw")
	press(t, &m, "enter")
	if !strings.Contains(m.View(), "v1 · added by you") {
		t.Fatalf("history not shown after password:\n%s", m.View())
	}
}
