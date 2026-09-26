// Annotations view: one variable's description and notes, full screen.
//
// The TUI could set a description and add a note but never show a note again,
// and the description lived only in the detail pane, which a terminal under
// 120 columns never draws. This view is the TUI's half of the portal's notes
// panel: read everything, add, edit, remove, and see who did what and when.
//
// Every write is a daemon call that the daemon authorizes and audits exactly
// as it does for `byn note` and the portal; nothing here decides policy. When a
// call needs the master password, the existing password overlay collects it
// and the parked call is replayed. The password is then kept for the life of
// this view only — so reading, editing and history do not ask again — and
// zeroed when it closes.
package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// annTyping is what the view's input line is collecting, if anything.
type annTyping int

const (
	annTypingNone annTyping = iota
	annTypingDescribe
	annTypingAdd
	annTypingEdit
)

// annConfirmClear is the ConfirmID used when the confirm is for clearing the
// description rather than removing a note (note ids are positive).
const annConfirmClear int64 = -1

// annState backs ModeAnnotations.
type annState struct {
	Name      string
	Scope     ipc.Scope // where the variable's annotations live
	Inherited bool      // the row is default's; so are its annotations
	Meta      ipc.SecretMeta

	Resp    ipc.AnnotationListResp
	Err     error
	Loaded  bool
	Cursor  int // 0 = the description; i > 0 = items()[i-1]
	Removed bool

	HistoryFor int64 // annotation whose history is open; 0 = none
	History    []ipc.AnnotationVersionView

	Typing    annTyping
	Buf       []rune
	EditID    int64
	ConfirmID int64 // note awaiting remove confirmation, or annConfirmClear

	// pw is the master password once the user has given it in this view.
	pw []byte
	// pending is the call to replay once the password overlay collects one.
	pending func(pw []byte) tea.Cmd
}

func (a *annState) wipe() {
	for i := range a.pw {
		a.pw[i] = 0
	}
	a.pw = nil
	for i := range a.Buf {
		a.Buf[i] = 0
	}
	a.Buf = nil
	a.pending = nil
}

// items are the notes the cursor moves over after the description: live ones,
// then — when asked for — removed ones.
func (a *annState) items() []ipc.AnnotationView {
	var live, gone []ipc.AnnotationView
	for _, n := range a.Resp.Notes {
		if n.RemovedAt != nil {
			gone = append(gone, n)
		} else {
			live = append(live, n)
		}
	}
	return append(live, gone...)
}

func (a *annState) selectedNote() (ipc.AnnotationView, bool) {
	it := a.items()
	if a.Cursor < 1 || a.Cursor > len(it) {
		return ipc.AnnotationView{}, false
	}
	return it[a.Cursor-1], true
}

func (a *annState) description() (ipc.AnnotationView, bool) {
	if len(a.Resp.Descriptions) == 0 {
		return ipc.AnnotationView{}, false
	}
	return a.Resp.Descriptions[0], true
}

// ---- messages and commands ------------------------------------------------

// annLoadedMsg is a fresh read of the variable's annotations.
type annLoadedMsg struct {
	Resp ipc.AnnotationListResp
	Err  error
}

// annHistoryMsg is one annotation's version history.
type annHistoryMsg struct {
	ID       int64
	Versions []ipc.AnnotationVersionView
	Err      error
}

// annOpMsg is the result of a write (describe, add, edit, remove).
type annOpMsg struct {
	Op  string
	Err error
}

func annTarget(name string) ipc.AnnotationTarget {
	return ipc.AnnotationTarget{Type: "entry", Name: name}
}

// annLoadCmd reads the description and notes. Without a credential the daemon
// answers with the description and NotesWithheld, not an error.
func annLoadCmd(c Client, scope ipc.Scope, name string, removed bool, pw []byte) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.AnnotationListResp
		err := c.Call(ipc.OpAnnotationList, ipc.AnnotationListReq{
			Scope: scope, Target: annTarget(name), IncludeRemoved: removed, Password: pw,
		}, &resp)
		return annLoadedMsg{Resp: resp, Err: err}
	}
}

func annHistoryCmd(c Client, scope ipc.Scope, name string, id int64, pw []byte) tea.Cmd {
	return func() tea.Msg {
		var resp ipc.AnnotationHistoryResp
		err := c.Call(ipc.OpAnnotationHistory, ipc.AnnotationHistoryReq{
			Scope: scope, Target: annTarget(name), ID: id, Password: pw,
		}, &resp)
		return annHistoryMsg{ID: id, Versions: resp.Versions, Err: err}
	}
}

func annDescribeCmd(c Client, scope ipc.Scope, name, text string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpAnnotationSet, ipc.AnnotationSetReq{
			Scope: scope, Target: annTarget(name), Text: text, Clear: text == "", Password: pw,
		}, &ipc.AnnotationSetResp{})
		op := "described"
		if text == "" {
			op = "description cleared"
		}
		return annOpMsg{Op: op, Err: err}
	}
}

func annAddCmd(c Client, scope ipc.Scope, name, text string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpAnnotationAdd, ipc.AnnotationAddReq{
			Scope: scope, Target: annTarget(name), Text: text, Password: pw,
		}, &ipc.AnnotationAddResp{})
		return annOpMsg{Op: "noted", Err: err}
	}
}

func annEditCmd(c Client, scope ipc.Scope, name string, id int64, text string, pw []byte) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpAnnotationEdit, ipc.AnnotationEditReq{
			Scope: scope, Target: annTarget(name), ID: id, Text: text, Password: pw,
		}, &ipc.AnnotationEditResp{})
		return annOpMsg{Op: "note updated", Err: err}
	}
}

func annRemoveCmd(c Client, scope ipc.Scope, name string, id int64, pw []byte) tea.Cmd {
	return func() tea.Msg {
		err := c.Call(ipc.OpAnnotationRemove, ipc.AnnotationRemoveReq{
			Scope: scope, Target: annTarget(name), ID: id, Password: pw,
		}, &ipc.AnnotationRemoveResp{})
		return annOpMsg{Op: "note removed", Err: err}
	}
}

// ---- opening and closing --------------------------------------------------

// openAnnotations opens the view on the entry under the cursor. An inherited
// row's annotations belong to default's variable, so that is where they are
// read and written.
func (m Model) openAnnotations() (tea.Model, tea.Cmd) {
	e := m.currentEntry()
	if e == nil {
		m.flash("select an entry first", false)
		return m, nil
	}
	scope := m.scope
	inherited := e.Source == "default" && envOrDefault(m.scope.Env) != "default"
	if inherited {
		scope.Env = "default"
	}
	m.ann = &annState{Name: e.Name, Scope: scope, Inherited: inherited, Meta: *e}
	m.Mode = ModeAnnotations
	return m, annLoadCmd(m.client, scope, e.Name, false, nil)
}

func (m Model) closeAnnotations() (tea.Model, tea.Cmd) {
	if m.ann != nil {
		m.ann.wipe()
	}
	m.ann = nil
	m.Mode = ModeNormal
	return m, tea.Batch(loadEntriesCmd(m.client, m.scope), loadAuditCmd(m.client, m.scope.Vault, 10))
}

// run issues call with the password this view holds (nil until given). If the
// daemon asks for one, the call is parked and the password overlay opens.
func (m Model) annRun(call func(pw []byte) tea.Cmd) (Model, tea.Cmd) {
	m.ann.pending = call
	return m, call(m.ann.pw)
}

// askPassword opens the password overlay for the parked call.
func (m Model) annAskPassword(cause string) Model {
	m.Mode = ModeAuthRequired
	m.authReq = &authReqState{Cause: cause, kind: authRetryAnnotation, priorMode: ModeAnnotations}
	return m
}

// annRetryWithPassword is the overlay's replay: keep a copy of the password
// for the rest of this view, then re-issue the parked call with it.
func (m Model) annRetryWithPassword(pw []byte) tea.Cmd {
	if m.ann == nil || m.ann.pending == nil {
		return nil
	}
	m.ann.pw = append([]byte(nil), pw...)
	return m.ann.pending(m.ann.pw)
}

// annFromOverlay settles a result that arrived while the password overlay was
// open. It reports whether it handled the message: a wrong password keeps the
// overlay up for another try; anything else closes it.
func (m Model) annFromOverlay(err error) (Model, bool) {
	if m.Mode != ModeAuthRequired || m.authReq == nil || m.authReq.kind != authRetryAnnotation {
		return m, false
	}
	if err != nil && (m.isAuthRequired(err) || isWrongPassword(err)) {
		m.authReq.retryErr = err.Error()
		if m.ann != nil {
			m.ann.wipePassword()
		}
		return m, true
	}
	m.authReq = nil
	m.Mode = ModeAnnotations
	return m, false
}

func (a *annState) wipePassword() {
	for i := range a.pw {
		a.pw[i] = 0
	}
	a.pw = nil
}

func isWrongPassword(err error) bool {
	var er *ipc.ErrResponse
	return errors.As(err, &er) && er.Code == ipc.CodeWrongPassword
}

// ---- results ----------------------------------------------------------------

func (m Model) handleAnnLoaded(msg annLoadedMsg) (tea.Model, tea.Cmd) {
	if m.ann == nil {
		return m, nil
	}
	err := msg.Err
	// A read that asks for everything is answered even when the password is
	// refused — with the notes withheld instead of an error. Asked for from
	// the password prompt, that means the password was not accepted.
	if err == nil && msg.Resp.NotesWithheld && m.Mode == ModeAuthRequired {
		err = &ipc.ErrResponse{Code: ipc.CodeWrongPassword, Message: "password not accepted"}
	}
	m, handled := m.annFromOverlay(err)
	if handled {
		return m, nil
	}
	if msg.Err != nil {
		m.ann.Err = msg.Err
		m.ann.Loaded = true
		return m, nil
	}
	m.ann.Resp, m.ann.Err, m.ann.Loaded = msg.Resp, nil, true
	if n := len(m.ann.items()); m.ann.Cursor > n {
		m.ann.Cursor = n
	}
	return m, nil
}

func (m Model) handleAnnHistory(msg annHistoryMsg) (tea.Model, tea.Cmd) {
	if m.ann == nil {
		return m, nil
	}
	m, handled := m.annFromOverlay(msg.Err)
	if handled {
		return m, nil
	}
	if msg.Err != nil {
		if m.isAuthRequired(msg.Err) && m.ann.pw == nil {
			return m.annAskPassword("a note's history holds every version of its text, so reading it needs the master password"), nil
		}
		m.flash("history failed: "+msg.Err.Error(), false)
		return m, nil
	}
	m.ann.HistoryFor, m.ann.History = msg.ID, msg.Versions
	return m, nil
}

func (m Model) handleAnnOp(msg annOpMsg) (tea.Model, tea.Cmd) {
	if m.ann == nil {
		return m, nil
	}
	m, handled := m.annFromOverlay(msg.Err)
	if handled {
		return m, nil
	}
	if msg.Err != nil {
		if m.isAuthRequired(msg.Err) && m.ann.pw == nil {
			return m.annAskPassword(authRequiredCause(msg.Err)), nil
		}
		m.flash(msg.Op+" failed: "+msg.Err.Error(), false)
		return m, nil
	}
	m.ann.pending = nil
	m.ann.HistoryFor, m.ann.History = 0, nil
	m.flash(msg.Op+" — "+m.ann.Name, true)
	return m, annLoadCmd(m.client, m.ann.Scope, m.ann.Name, m.ann.Removed, m.ann.pw)
}

// ---- keys -----------------------------------------------------------------

func (m Model) keyAnnotations(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a := m.ann
	if a == nil {
		m.Mode = ModeNormal
		return m, nil
	}
	k := msg.String()

	// The input line owns the keyboard while it is open.
	if a.Typing != annTypingNone {
		switch k {
		case "esc":
			a.Typing, a.Buf, a.EditID = annTypingNone, nil, 0
			return m, nil
		case "enter":
			return m.annSubmit()
		case "backspace":
			if len(a.Buf) > 0 {
				a.Buf = a.Buf[:len(a.Buf)-1]
			}
			return m, nil
		case "ctrl+u":
			a.Buf = nil
			return m, nil
		}
		if rs := msg.Runes; len(rs) > 0 {
			a.Buf = append(a.Buf, rs...)
		} else if k == " " || k == "space" {
			a.Buf = append(a.Buf, ' ')
		}
		return m, nil
	}

	// A pending remove/clear takes y or n.
	if a.ConfirmID != 0 {
		id := a.ConfirmID
		a.ConfirmID = 0
		if k != "y" {
			return m, nil
		}
		scope, name := a.Scope, a.Name
		c := m.client
		if id == annConfirmClear {
			nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annDescribeCmd(c, scope, name, "", pw) })
			return nm, cmd
		}
		nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annRemoveCmd(c, scope, name, id, pw) })
		return nm, cmd
	}

	switch k {
	case "esc", "q":
		return m.closeAnnotations()
	case "j", "down":
		if a.Cursor < len(a.items()) {
			a.Cursor++
			a.HistoryFor, a.History = 0, nil
		}
		return m, nil
	case "k", "up":
		if a.Cursor > 0 {
			a.Cursor--
			a.HistoryFor, a.History = 0, nil
		}
		return m, nil
	case "e", "enter", "i":
		if a.Cursor == 0 {
			if a.Meta.DescriptionSource == ".byn" && len(a.Resp.Descriptions) == 0 {
				m.flash("this description comes from the trusted .byn — writing one here adds the vault's own", true)
			}
			d, _ := a.description()
			a.Typing, a.Buf = annTypingDescribe, []rune(d.Body)
			return m, nil
		}
		n, ok := a.selectedNote()
		if !ok {
			return m, nil
		}
		if n.RemovedAt != nil {
			m.flash("a removed note cannot be edited — its history is under h", false)
			return m, nil
		}
		a.Typing, a.Buf, a.EditID = annTypingEdit, []rune(n.Body), n.ID
		return m, nil
	case "a":
		if a.Resp.NotesWithheld {
			m.flash("press p to authorize first — then notes can be read and added", false)
			return m, nil
		}
		a.Typing, a.Buf = annTypingAdd, nil
		return m, nil
	case "d", "x":
		if a.Cursor == 0 {
			if _, ok := a.description(); ok {
				a.ConfirmID = annConfirmClear
			}
			return m, nil
		}
		if n, ok := a.selectedNote(); ok && n.RemovedAt == nil {
			a.ConfirmID = n.ID
		}
		return m, nil
	case "h":
		id := int64(0)
		if a.Cursor == 0 {
			if d, ok := a.description(); ok {
				id = d.ID
			}
		} else if n, ok := a.selectedNote(); ok {
			id = n.ID
		}
		if id == 0 {
			return m, nil
		}
		if a.HistoryFor == id {
			a.HistoryFor, a.History = 0, nil
			return m, nil
		}
		scope, name, c := a.Scope, a.Name, m.client
		nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annHistoryCmd(c, scope, name, id, pw) })
		return nm, cmd
	case "r":
		a.Removed = !a.Removed
		a.HistoryFor, a.History = 0, nil
		return m, annLoadCmd(m.client, a.Scope, a.Name, a.Removed, a.pw)
	case "R":
		return m, annLoadCmd(m.client, a.Scope, a.Name, a.Removed, a.pw)
	case "p":
		if !a.Resp.NotesWithheld && a.pw != nil {
			return m, nil
		}
		scope, name, removed, c := a.Scope, a.Name, a.Removed, m.client
		a.pending = func(pw []byte) tea.Cmd { return annLoadCmd(c, scope, name, removed, pw) }
		return m.annAskPassword("reading notes needs the master password (no session for this terminal)"), nil
	}
	return m, nil
}

// annSubmit sends what the input line holds.
func (m Model) annSubmit() (tea.Model, tea.Cmd) {
	a := m.ann
	text := strings.TrimSpace(string(a.Buf))
	typing, id := a.Typing, a.EditID
	a.Typing, a.Buf, a.EditID = annTypingNone, nil, 0
	scope, name, c := a.Scope, a.Name, m.client

	switch typing {
	case annTypingDescribe:
		if d, ok := a.description(); (ok && d.Body == text) || (!ok && text == "") {
			return m, nil
		}
		nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annDescribeCmd(c, scope, name, text, pw) })
		return nm, cmd
	case annTypingAdd:
		if text == "" {
			return m, nil
		}
		nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annAddCmd(c, scope, name, text, pw) })
		return nm, cmd
	case annTypingEdit:
		if n, ok := a.selectedNote(); !ok || text == "" || n.Body == text {
			return m, nil
		}
		nm, cmd := m.annRun(func(pw []byte) tea.Cmd { return annEditCmd(c, scope, name, id, text, pw) })
		return nm, cmd
	}
	return m, nil
}

// ---- rendering --------------------------------------------------------------

func (m Model) renderAnnotations(w, h int) string {
	a := m.ann
	var lines []string
	title := "NOTES & DESCRIPTION — " + a.Name
	lines = append(lines, m.styles.SectionHeader.Render(title))
	if a.Inherited {
		lines = append(lines, m.styles.StatusInherited.Render("  inherited from default — these are default's, and changes here change default's"))
	}
	lines = append(lines, "")

	selStart := 0 // first line of the selected item, to keep it on screen
	mark := func(i int) string {
		if i == a.Cursor {
			selStart = len(lines)
			return m.styles.StatusNew.Render("▸ ")
		}
		return "  "
	}
	bodyW := w - 6
	if bodyW < 20 {
		bodyW = 20
	}

	// Description.
	lines = append(lines, mark(0)+m.styles.EntryName.Render("DESCRIPTION")+
		m.styles.EntryMeta.Render("  plaintext — anything reaching byn can read it, agents included"))
	d, hasDesc := a.description()
	switch {
	case !a.Loaded:
		lines = append(lines, "    "+m.styles.Placeholder.Render("loading…"))
	case hasDesc:
		for _, ln := range wrapPlain(d.Body, bodyW) {
			lines = append(lines, "    "+m.styles.DetailValue.Render(ln))
		}
		lines = append(lines, "    "+m.styles.EntryMeta.Render(annByline(d)))
	default:
		lines = append(lines, "    "+m.styles.Placeholder.Render("(none — e to write one)"))
	}
	if a.Meta.DescriptionSource == ".byn" {
		lines = append(lines, "    "+m.styles.DetailWarn.Render("the trusted .byn also declares one (edit the .byn to change it):"))
		for _, ln := range wrapPlain(a.Meta.Description, bodyW) {
			lines = append(lines, "    "+m.styles.EntryMeta.Render(ln))
		}
	}
	if a.HistoryFor != 0 && hasDesc && a.HistoryFor == d.ID && a.Cursor == 0 {
		lines = append(lines, m.annHistoryLines(bodyW)...)
	}
	lines = append(lines, "")

	// Notes.
	head := "NOTES"
	if n := a.Resp.NoteCount; n > 0 {
		head += fmt.Sprintf(" (%d)", n)
	}
	lines = append(lines, "  "+m.styles.EntryName.Render(head)+
		m.styles.EntryMeta.Render("  encrypted — only you can read these"))
	switch {
	case a.Err != nil:
		lines = append(lines, "    "+m.styles.Error.Render("could not read: "+a.Err.Error()))
	case a.Resp.NotesWithheld:
		lines = append(lines, "    "+m.styles.DetailWarn.Render(fmt.Sprintf(
			"%d note(s) here — p to enter the master password and read them", a.Resp.NoteCount)))
	case a.Loaded && len(a.items()) == 0:
		lines = append(lines, "    "+m.styles.Placeholder.Render("(no notes — a to add one)"))
	}
	for i, n := range a.items() {
		if n.RemovedAt != nil && (i == 0 || a.items()[i-1].RemovedAt == nil) {
			lines = append(lines, "", "  "+m.styles.EntryMeta.Render("REMOVED — kept in history; gone for good when "+a.Name+" is deleted"))
		}
		by := annByline(n)
		if n.RemovedAt != nil {
			by += " · removed " + n.RemovedAt.Local().Format("2006-01-02 15:04")
		}
		lines = append(lines, mark(i+1)+m.styles.EntryMeta.Render(by))
		style := m.styles.DetailValue
		if n.RemovedAt != nil {
			style = m.styles.EntryMeta.Strikethrough(true)
		}
		for _, ln := range wrapPlain(n.Body, bodyW) {
			lines = append(lines, "    "+style.Render(ln))
		}
		if a.HistoryFor == n.ID && a.Cursor == i+1 {
			lines = append(lines, m.annHistoryLines(bodyW)...)
		}
	}

	footer := m.annFooter(w)
	room := h - len(footer) - 1
	if room < 3 {
		room = 3
	}
	// Scroll so the selected item's first line stays in view.
	if len(lines) > room && selStart >= room-2 {
		off := selStart - (room - 4)
		if off > len(lines)-room {
			off = len(lines) - room
		}
		if off > 0 {
			lines = lines[off:]
		}
	}
	if len(lines) > room {
		lines = lines[:room]
	}
	for len(lines) < room {
		lines = append(lines, "")
	}
	lines = append(lines, "")
	lines = append(lines, footer...)
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	for i, ln := range lines {
		lines[i] = padRightLipgloss(ln, w)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// annByline says who wrote an annotation and when, and when it last changed.
func annByline(v ipc.AnnotationView) string {
	s := "added " + v.CreatedAt.Local().Format("2006-01-02 15:04") + " by " + annWho(v.Author, v.AuthorComm)
	if !v.UpdatedAt.IsZero() && v.UpdatedAt.Sub(v.CreatedAt) >= time.Second && v.RemovedAt == nil {
		s += " · edited " + v.UpdatedAt.Local().Format("2006-01-02 15:04")
	}
	return s
}

func annWho(author, comm string) string {
	if author == "agent" {
		if comm != "" {
			return "agent " + comm
		}
		return "an agent"
	}
	return "you"
}

var annVerbs = map[string]string{"create": "added", "edit": "edited", "delete": "removed", "set": "set"}

func (m Model) annHistoryLines(w int) []string {
	out := []string{"    " + m.styles.SectionHeader.Render("history")}
	if len(m.ann.History) == 0 {
		return append(out, "      "+m.styles.Placeholder.Render("(no versions)"))
	}
	for _, v := range m.ann.History {
		verb := annVerbs[v.Op]
		if verb == "" {
			verb = v.Op
		}
		head := fmt.Sprintf("v%d · %s by %s · %s", v.VersionNo, verb, annWho(v.Author, v.AuthorComm),
			v.CreatedAt.Local().Format("2006-01-02 15:04"))
		style := m.styles.EntryMeta
		if v.Op == "delete" {
			style = m.styles.AuditDenied
		}
		out = append(out, "      "+style.Render(head))
		for _, ln := range wrapPlain(v.Body, w-4) {
			if v.Body == "" {
				break
			}
			out = append(out, "        "+m.styles.DetailValue.Render(ln))
		}
	}
	return out
}

// annFooter is the input line, the confirm prompt, or the keys.
func (m Model) annFooter(w int) []string {
	a := m.ann
	switch {
	case a.Typing != annTypingNone:
		label := map[annTyping]string{
			annTypingDescribe: "description (plaintext — never a secret): ",
			annTypingAdd:      "new note (encrypted): ",
			annTypingEdit:     "edit note: ",
		}[a.Typing]
		text := string(a.Buf)
		if room := w - lipgloss.Width(label) - 2; room > 8 && len([]rune(text)) > room {
			r := []rune(text)
			text = "…" + string(r[len(r)-room+1:])
		}
		return []string{
			m.styles.SectionHeader.Render(label) + text + "▏",
			m.styles.EntryMeta.Render("enter save · esc cancel · ctrl+u clear"),
		}
	case a.ConfirmID == annConfirmClear:
		return []string{m.styles.DetailWarn.Render("clear the description? its text stays in history.  y yes · any other key no")}
	case a.ConfirmID != 0:
		return []string{m.styles.DetailWarn.Render("remove this note? its text stays in history, so a changed note stays traceable.  y yes · any other key no")}
	}
	keys := []string{"j/k move", "e edit", "a add note", "d remove", "h history"}
	if a.Removed {
		keys = append(keys, "r hide removed")
	} else {
		keys = append(keys, "r show removed")
	}
	if a.Resp.NotesWithheld {
		keys = append(keys, "p password")
	}
	keys = append(keys, "esc close")
	return []string{m.styles.EntryMeta.Render(strings.Join(keys, " · "))}
}
