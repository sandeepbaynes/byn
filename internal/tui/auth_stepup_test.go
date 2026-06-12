package tui

// Tests for the ModeAuthRequired "Authorize" password step-up overlay.
//
// Covered:
//   - auth_required on reveal (R) opens the overlay
//   - auth_required on edit prefetch (i → INSERT) opens the overlay
//   - auth_required on put (commitEdit INSERT) opens the overlay
//   - auth_required on delete opens the overlay
//   - auth_required on rename opens the overlay
//   - Submit with correct password retries the op (assert request body)
//   - Submit with empty password shows inline error, stays in overlay
//   - Wrong password response stays in overlay with error
//   - Esc cancels and surfaces flash message, returns to NORMAL
//   - Snapshot of overlay at standard size (written to testdata/)

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// authFakeClient injects an auth_required error for specific ops on the
// first call, then succeeds on the retry by delegating to fakeClient.
type authFakeClient struct {
	// lastOp / lastReq are the most recent call's details.
	lastOp  ipc.Op
	lastReq any

	// When authRequiredOps contains an op, the first call returns
	// CodeAuthRequired; subsequent calls for the same op succeed.
	authRequiredOps map[ipc.Op]bool
	calledOps       map[ipc.Op]int // call count per op
}

func newAuthFakeClient(authRequiredForOps ...ipc.Op) *authFakeClient {
	c := &authFakeClient{
		authRequiredOps: make(map[ipc.Op]bool),
		calledOps:       make(map[ipc.Op]int),
	}
	for _, op := range authRequiredForOps {
		c.authRequiredOps[op] = true
	}
	return c
}

func (c *authFakeClient) Call(op ipc.Op, req, resp any) error {
	c.lastOp = op
	c.lastReq = req
	c.calledOps[op]++
	// First call to an auth-required op returns CodeAuthRequired.
	if c.authRequiredOps[op] && c.calledOps[op] == 1 {
		return &ipc.ErrResponse{
			Code:    ipc.CodeAuthRequired,
			Message: "authorization required",
		}
	}
	// Second+ call: delegate to fakeClient for proper response.
	return fakeClient{}.Call(op, req, resp)
}

// wrongPWClient returns a wrong_password error on all calls.
type wrongPWClient struct {
	lastOp  ipc.Op
	lastReq any
}

func (c *wrongPWClient) Call(op ipc.Op, req, _ any) error {
	c.lastOp = op
	c.lastReq = req
	return &ipc.ErrResponse{Code: ipc.CodeWrongPassword, Message: "wrong password"}
}

// setupAuthModel builds a fully-loaded model at standard size (100×30) with
// FocusContent and the entry cursor on the first entry ("API_KEY").
func setupAuthModel(t *testing.T, c Client) Model {
	t.Helper()
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := NewModel(c, "test", scope)
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = mAny.(Model)
	runQueue(t, &m, m.Init())
	// Move to content pane; first entry (API_KEY) is at cursor 0.
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = mAny.(Model)
	return m
}

// ---- Reveal (R) triggers overlay ----------------------------------------

func TestAuthRequired_RevealOpensOverlay(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	// Press R to reveal; first OpGet returns auth_required.
	mAny, cmd := m.Update(key('R'))
	m = mAny.(Model)
	// Run the returned command (getValueCmd → authRetryMsg/entryValueMsg).
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil {
		t.Fatal("authReq is nil")
	}
	if m.authReq.kind != authRetryGet {
		t.Fatalf("authReq.kind = %v, want authRetryGet", m.authReq.kind)
	}
	if m.authReq.priorMode != ModeReveal {
		t.Fatalf("priorMode = %v, want ModeReveal", m.authReq.priorMode)
	}
	if !strings.Contains(m.authReq.Cause, "authorization") {
		t.Fatalf("Cause %q doesn't mention authorization", m.authReq.Cause)
	}
}

// ---- Insert prefill (i) triggers overlay --------------------------------

func TestAuthRequired_InsertPrefillOpensOverlay(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	// Press i to start INSERT; this fetches the entry's value.
	mAny, cmd := m.Update(key('i'))
	m = mAny.(Model)
	// Run the getValueCmd.
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil || m.authReq.kind != authRetryGet {
		t.Fatalf("authReq = %+v", m.authReq)
	}
	if m.authReq.priorMode != ModeInsert {
		t.Fatalf("priorMode = %v, want ModeInsert", m.authReq.priorMode)
	}
}

// ---- Submit retries op with password (get) ------------------------------

func TestAuthRequired_SubmitRetriesGetWithPassword(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	// Trigger auth_required on reveal.
	mAny, cmd := m.Update(key('R'))
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	if m.Mode != ModeAuthRequired {
		t.Fatalf("not in ModeAuthRequired, got %v", m.Mode)
	}

	// Type password.
	m = typeRunes(m, "s3cret")

	// Submit.
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)

	// Run the retry command.
	if cmd == nil {
		t.Fatal("no retry command returned after Enter")
	}
	msg := cmd()
	mAny, _ = m.Update(msg)
	m = mAny.(Model)

	// Verify the retry used the right op and password.
	if c.lastOp != ipc.OpGet {
		t.Fatalf("retry op = %v, want OpGet", c.lastOp)
	}
	req, ok := c.lastReq.(ipc.GetReq)
	if !ok {
		t.Fatalf("lastReq is %T, not GetReq", c.lastReq)
	}
	if string(req.Password) != "s3cret" {
		t.Fatalf("retry password = %q, want %q", string(req.Password), "s3cret")
	}

	// After successful retry the mode should be ModeReveal.
	if m.Mode != ModeReveal {
		t.Fatalf("mode after retry = %v, want ModeReveal", m.Mode)
	}
}

// ---- Submit retries put with password -----------------------------------

func TestAuthRequired_SubmitRetriesPutWithPassword(t *testing.T) {
	c := newAuthFakeClient(ipc.OpPut)
	m := setupAuthModel(t, c)

	// Enter INSERT for API_KEY.
	mAny, cmd := m.Update(key('i'))
	m = mAny.(Model)
	// getValueCmd succeeds (OpGet not auth-required).
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	// Type new value.
	m = typeRunes(m, "newval")
	// Commit with :w. Enter INSERT mode first so the colon opens the
	// command palette from within an edit context (FromEdit=true).
	m.Mode = ModeInsert
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	m = mAny.(Model)
	m = typeRunes(m, "w")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	// Run the putValueCmd — first call returns auth_required.
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v after put auth_required, want ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil || m.authReq.kind != authRetryPut {
		t.Fatalf("authReq = %+v", m.authReq)
	}

	// Type password and submit.
	m = typeRunes(m, "pw123")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command after Enter")
	}
	msg := cmd()
	mAny, _ = m.Update(msg)
	m = mAny.(Model)

	// The retry should have used OpPut with the password.
	if c.lastOp != ipc.OpPut {
		t.Fatalf("retry op = %v, want OpPut", c.lastOp)
	}
	req, ok := c.lastReq.(ipc.PutReq)
	if !ok {
		t.Fatalf("lastReq is %T", c.lastReq)
	}
	if string(req.Password) != "pw123" {
		t.Fatalf("retry password = %q", string(req.Password))
	}
	if m.Mode != ModeNormal {
		t.Fatalf("mode after put retry = %v, want NORMAL", m.Mode)
	}
}

// ---- authRetryAddCmd (createOnly/ModeAdd) test --------------------------

func TestAuthRequired_SubmitRetriesAddWithPassword(t *testing.T) {
	c := newAuthFakeClient(ipc.OpPut)
	m := setupAuthModel(t, c)

	// Press 'a' to enter ADD-ENTRY mode.
	mAny, _ := m.Update(key('a'))
	m = mAny.(Model)
	if m.Mode != ModeAdd {
		t.Fatalf("mode = %v, want ModeAdd", m.Mode)
	}

	// Type a new entry name, tab to value, type a value.
	m = typeRunes(m, "NEW_SECRET")
	m = sendKey(m, tea.KeyMsg{Type: tea.KeyTab})
	m = typeRunes(m, "secretval")

	// Commit via :w — triggers addEntryCmd (CreateOnly=true).
	// Enter INSERT-like command context from ADD mode.
	m.Mode = ModeAdd
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	m = mAny.(Model)
	m = typeRunes(m, "w")
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	// Run the addEntryCmd — first OpPut returns auth_required.
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v after add auth_required, want ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil {
		t.Fatal("authReq is nil")
	}
	if m.authReq.kind != authRetryPut {
		t.Fatalf("authReq.kind = %v, want authRetryPut", m.authReq.kind)
	}
	if !m.authReq.createOnly {
		t.Fatal("authReq.createOnly should be true for ADD-ENTRY path")
	}

	// Type password and submit.
	m = typeRunes(m, "addpw")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command after Enter")
	}
	retryMsg := cmd()
	mAny, _ = m.Update(retryMsg)
	m = mAny.(Model)

	// The retry should have used OpPut with CreateOnly and the password.
	if c.lastOp != ipc.OpPut {
		t.Fatalf("retry op = %v, want OpPut", c.lastOp)
	}
	req, ok := c.lastReq.(ipc.PutReq)
	if !ok {
		t.Fatalf("lastReq is %T", c.lastReq)
	}
	if string(req.Password) != "addpw" {
		t.Fatalf("retry password = %q, want %q", string(req.Password), "addpw")
	}
	if !req.CreateOnly {
		t.Fatal("retry must use CreateOnly=true for add-entry retry path")
	}
	if m.Mode != ModeNormal {
		t.Fatalf("mode after add retry = %v, want NORMAL", m.Mode)
	}
}

// ---- Submit retries delete with password --------------------------------

func TestAuthRequired_SubmitRetriesDeleteWithPassword(t *testing.T) {
	c := newAuthFakeClient(ipc.OpDelete)
	m := setupAuthModel(t, c)

	// d d to start delete confirm.
	m = sendKey(m, key('d'))
	m = sendKey(m, key('d'))
	if m.Mode != ModeConfirmDelete {
		t.Fatalf("mode = %v, want CONFIRM", m.Mode)
	}

	// Confirm with d — dispatches deleteEntryCmd → auth_required.
	mAny, cmd := m.Update(key('d'))
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want ModeAuthRequired", m.Mode)
	}

	m = typeRunes(m, "del_pw")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command")
	}
	// Fold the retry result through Update (not discarded).
	retryMsg := cmd()
	mAny, _ = m.Update(retryMsg)
	m = mAny.(Model)

	if c.lastOp != ipc.OpDelete {
		t.Fatalf("retry op = %v, want OpDelete", c.lastOp)
	}
	req, ok := c.lastReq.(ipc.DeleteReq)
	if !ok {
		t.Fatalf("lastReq is %T", c.lastReq)
	}
	if string(req.Password) != "del_pw" {
		t.Fatalf("password = %q", string(req.Password))
	}
	// After successful delete retry the model should be back in NORMAL.
	if m.Mode != ModeNormal {
		t.Fatalf("mode after delete retry = %v, want NORMAL", m.Mode)
	}
}

// ---- Submit retries rename with password --------------------------------

func TestAuthRequired_SubmitRetriesRenameWithPassword(t *testing.T) {
	c := newAuthFakeClient(ipc.OpRename)
	m := setupAuthModel(t, c)

	// Press r to rename; the entry is API_KEY.
	mAny, _ := m.Update(key('r'))
	m = mAny.(Model)
	if m.Mode != ModeRename {
		t.Fatalf("mode = %v, want RENAME", m.Mode)
	}
	// Clear existing name and type a new one.
	for range "API_KEY" {
		m = sendKey(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	m = typeRunes(m, "NEW_KEY")
	// Commit via :w.
	m.Mode = ModeRename
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{':'}})
	m = mAny.(Model)
	m = typeRunes(m, "w")
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v, want ModeAuthRequired", m.Mode)
	}

	m = typeRunes(m, "rnpw")
	mAny, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command")
	}
	// Fold the retry result through Update (not discarded).
	retryMsg := cmd()
	mAny, _ = m.Update(retryMsg)
	m = mAny.(Model)

	if c.lastOp != ipc.OpRename {
		t.Fatalf("retry op = %v, want OpRename", c.lastOp)
	}
	req, ok := c.lastReq.(ipc.RenameReq)
	if !ok {
		t.Fatalf("lastReq is %T", c.lastReq)
	}
	if string(req.Password) != "rnpw" {
		t.Fatalf("password = %q", string(req.Password))
	}
	// Assert OldName (original) and NewName (new) are carried through.
	if req.OldName != "API_KEY" {
		t.Fatalf("OldName = %q, want API_KEY", req.OldName)
	}
	if req.NewName != "NEW_KEY" {
		t.Fatalf("NewName = %q, want NEW_KEY", req.NewName)
	}
	// After successful rename retry the model should be back in NORMAL.
	if m.Mode != ModeNormal {
		t.Fatalf("mode after rename retry = %v, want NORMAL", m.Mode)
	}
}

// ---- Empty password shows inline error, stays in overlay ----------------

func TestAuthRequired_EmptyPasswordShowsError(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	mAny, cmd := m.Update(key('R'))
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	if m.Mode != ModeAuthRequired {
		t.Fatalf("not in auth mode: %v", m.Mode)
	}

	// Submit without typing a password.
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v after empty-pw submit, want still in ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil || m.authReq.retryErr == "" {
		t.Fatalf("expected retryErr, got %+v", m.authReq)
	}
	if !strings.Contains(m.authReq.retryErr, "password required") {
		t.Fatalf("retryErr = %q, want 'password required'", m.authReq.retryErr)
	}
}

// ---- Wrong password stays in overlay ------------------------------------

func TestAuthRequired_WrongPasswordStaysInOverlay(t *testing.T) {
	c := &wrongPWClient{}
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := NewModel(c, "test", scope)
	mAny, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = mAny.(Model)
	// Seed necessary state manually (skip full Init to avoid wrong-pw on status).
	m.entries = []ipc.SecretMeta{{Name: "API_KEY"}}
	m.Focus = FocusContent
	m.Mode = ModeNormal

	// Manually put model into ModeAuthRequired state (simulates prior auth_required).
	m.authReq = &authReqState{
		Cause:     "authorization required",
		kind:      authRetryGet,
		priorMode: ModeReveal,
		scope:     scope,
		name:      "API_KEY",
	}
	m.Mode = ModeAuthRequired

	// Type password and submit — the client always returns wrong_password.
	m = typeRunes(m, "badpw")
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command")
	}
	msg := cmd()
	mAny, _ = m.Update(msg)
	m = mAny.(Model)

	if m.Mode != ModeAuthRequired {
		t.Fatalf("mode = %v after wrong pw, want ModeAuthRequired", m.Mode)
	}
	if m.authReq == nil || m.authReq.retryErr == "" {
		t.Fatalf("expected retryErr after wrong pw, got %+v", m.authReq)
	}
	if !strings.Contains(m.authReq.retryErr, "wrong_password") && !strings.Contains(m.authReq.retryErr, "wrong password") {
		t.Fatalf("retryErr = %q doesn't mention wrong password", m.authReq.retryErr)
	}
}

// ---- Esc cancels and flashes original cause -----------------------------

func TestAuthRequired_EscCancelsAndFlashes(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	mAny, cmd := m.Update(key('R'))
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	if m.Mode != ModeAuthRequired {
		t.Fatalf("not in auth mode: %v", m.Mode)
	}

	// Press Esc.
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = mAny.(Model)

	if m.Mode != ModeNormal {
		t.Fatalf("mode = %v after ESC, want NORMAL", m.Mode)
	}
	if m.authReq != nil {
		t.Fatal("authReq should be nil after ESC")
	}
	if !strings.Contains(m.flashMsg, "auth_required") {
		t.Fatalf("flashMsg = %q, want auth_required mentioned", m.flashMsg)
	}
}

// ---- Overlay renders correctly (snapshot) --------------------------------

func TestAuthRequired_Snapshot(t *testing.T) {
	c := newAuthFakeClient(ipc.OpGet)
	m := setupAuthModel(t, c)

	// Trigger auth_required on reveal to get into overlay state.
	mAny, cmd := m.Update(key('R'))
	m = mAny.(Model)
	if cmd != nil {
		msg := cmd()
		mAny, _ = m.Update(msg)
		m = mAny.(Model)
	}
	if m.Mode != ModeAuthRequired {
		t.Fatalf("expected ModeAuthRequired, got %v", m.Mode)
	}

	view := m.View()
	body := stripANSI(view) + "\n"
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join("testdata", "auth-required.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// Sanity: the overlay must contain the title and hint.
	if !strings.Contains(view, "Authorize") {
		t.Errorf("snapshot missing 'Authorize':\n%s", body)
	}
	if !strings.Contains(view, "authorization") {
		t.Errorf("snapshot missing cause 'authorization':\n%s", body)
	}
	if !strings.Contains(view, "ESC cancel") {
		t.Errorf("snapshot missing ESC hint:\n%s", body)
	}
}

// ---- Overlay view string includes retryErr when set --------------------

func TestAuthRequired_OverlayShowsRetryErr(t *testing.T) {
	m := Model{
		styles: NewStyles(),
		Width:  100, Height: 30,
		Layout:  Compute(100, 30),
		Mode:    ModeAuthRequired,
		authReq: &authReqState{Cause: "authorization required", retryErr: "wrong_password: bad"},
	}
	view := m.View()
	stripped := stripANSI(view)
	if !strings.Contains(stripped, "wrong_password") {
		t.Errorf("overlay missing retryErr in view:\n%s", stripped)
	}
}

// ---- Value-zeroing invariant (authReqState.value) -----------------------
//
// The invariant: authReqState.value (the secret being written) MUST be
// zeroed on every exit from ModeAuthRequired. The tests below verify that
// esc/cancel and successful submit both honour this invariant. ctrl+c is
// tested indirectly — the same zeroing block in keyAuthRequired fires.

// TestAuthRequired_EscZeroesValue verifies that pressing Esc zeros the
// value buffer before releasing the authReq reference.
func TestAuthRequired_EscZeroesValue(t *testing.T) {
	c := newAuthFakeClient(ipc.OpPut)
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := Model{
		client:  c,
		styles:  NewStyles(),
		Width:   100,
		Height:  30,
		Layout:  Compute(100, 30),
		entries: []ipc.SecretMeta{{Name: "DB_PASS"}},
		Focus:   FocusContent,
	}
	// Seed value payload directly — simulates a put op that triggered auth_required.
	payload := []byte("super-secret-value")
	m.authReq = &authReqState{
		Cause: "authorization required",
		kind:  authRetryPut,
		scope: scope,
		name:  "DB_PASS",
		value: payload,
	}
	m.Mode = ModeAuthRequired

	// Press Esc — must zero and clear value before setting authReq = nil.
	mAny, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = mAny.(Model)

	if m.Mode != ModeNormal {
		t.Fatalf("mode = %v after ESC, want NORMAL", m.Mode)
	}
	if m.authReq != nil {
		t.Fatal("authReq must be nil after ESC")
	}
	// The payload backing array should be zeroed.
	for i, b := range payload {
		if b != 0 {
			t.Errorf("payload[%d] = %02x after ESC, want 0 (value not zeroed)", i, b)
		}
	}
}

// TestAuthRequired_SubmitZeroesValue verifies that after a successful retry
// submit, handleAuthRetry zeros the put payload before releasing authReq.
func TestAuthRequired_SubmitZeroesValue(t *testing.T) {
	// Use fakeClient (always succeeds) because we are injecting the
	// authReqState directly — the first call is the retry, and it should
	// succeed so that handleAuthRetry runs.
	c := fakeClient{}
	scope := ipc.Scope{Vault: "default", Project: "billing", Env: "staging"}
	m := Model{
		client:  c,
		styles:  NewStyles(),
		Width:   100,
		Height:  30,
		Layout:  Compute(100, 30),
		entries: []ipc.SecretMeta{{Name: "API_KEY"}},
		Focus:   FocusContent,
	}

	// Directly set up ModeAuthRequired with a value payload (simulates the
	// put op path: the edit form submitted, daemon returned auth_required,
	// and the value was stored in authReq.value for retry).
	payload := []byte("new-secret-value")
	m.authReq = &authReqState{
		Cause:     "authorization required",
		kind:      authRetryPut,
		scope:     scope,
		name:      "API_KEY",
		value:     payload,
		priorMode: ModeNormal,
	}
	m.Mode = ModeAuthRequired

	// Type password and submit.
	m = typeRunes(m, "mypw")
	mAny, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if cmd == nil {
		t.Fatal("no retry command after Enter")
	}
	// Run the retry command (fakeClient always succeeds).
	retryMsg := cmd()
	mAny, _ = m.Update(retryMsg)
	m = mAny.(Model)

	if m.Mode != ModeNormal {
		t.Fatalf("mode = %v after successful retry, want NORMAL", m.Mode)
	}
	if m.authReq != nil {
		t.Fatal("authReq must be nil after successful retry")
	}
	// The payload backing array should be zeroed by handleAuthRetry.
	for i, b := range payload {
		if b != 0 {
			t.Errorf("payload[%d] = %02x after submit success, want 0 (value not zeroed by handleAuthRetry)", i, b)
		}
	}
}
