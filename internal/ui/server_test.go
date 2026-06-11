package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// fakeDisp is a canned Dispatcher for handler tests.
type fakeDisp struct {
	wrongPassword bool
	revealValue   string
	dupOnCreate   bool   // OpPut with CreateOnly → already_exists
	lastPassword  []byte // password decoded from the last delete-family op
	lastOldPw     []byte // old_password from the last passwd op
	lastNewPw     []byte // new_password from the last passwd op
}

func (f *fakeDisp) Dispatch(_ context.Context, env *ipc.Envelope) *ipc.Envelope {
	mk := func(body any) *ipc.Envelope {
		resp, err := ipc.NewResponse(env.ID, body)
		if err != nil {
			return ipc.NewError(env.ID, ipc.CodeInternal, err.Error(), "")
		}
		return resp
	}
	switch env.Op {
	case ipc.OpStatus:
		return mk(ipc.StatusResp{Vaults: []ipc.VaultSummary{{Name: "default", Initialized: true, Locked: true}}})
	case ipc.OpVaultUnlock:
		if f.wrongPassword {
			return ipc.NewError(env.ID, ipc.CodeWrongPassword, "could not unlock vault", "verify password")
		}
		return mk(ipc.VaultUnlockResp{})
	case ipc.OpVaultInit:
		return mk(ipc.VaultInitResp{})
	case ipc.OpVaultLock:
		return mk(ipc.VaultLockResp{Locked: 1})
	case ipc.OpProjectList:
		return mk(ipc.ProjectListResp{Projects: []ipc.ProjectInfo{{Name: "default"}}})
	case ipc.OpEnvList:
		return mk(ipc.EnvListResp{Envs: []ipc.EnvInfo{{Name: "default", IsDefault: true}}})
	case ipc.OpList:
		return mk(ipc.ListResp{Secrets: []ipc.SecretMeta{{Name: "API_KEY", Source: "scope"}}})
	case ipc.OpGet:
		return mk(ipc.GetResp{Name: "API_KEY", Value: []byte(f.revealValue), Source: "scope"})
	case ipc.OpPut:
		if f.dupOnCreate {
			var pr ipc.PutReq
			_ = ipc.DecodeBody(ipc.BodyReq, env, &pr)
			if pr.CreateOnly {
				return ipc.NewError(env.ID, ipc.CodeAlreadyExists, "secret already exists", "")
			}
		}
		return mk(struct{}{})
	case ipc.OpDelete, ipc.OpProjectDelete, ipc.OpEnvDelete, ipc.OpVaultDelete,
		ipc.OpVaultRename, ipc.OpProjectRename, ipc.OpEnvRename:
		// These reqs share a `password` field — capture it so tests can
		// assert the portal forwards the authorizing password.
		var pw struct {
			Password []byte `json:"password"`
		}
		_ = ipc.DecodeBody(ipc.BodyReq, env, &pw)
		f.lastPassword = pw.Password
		return mk(struct{}{})
	case ipc.OpVaultPasswd:
		var pw struct {
			Old []byte `json:"old_password"`
			New []byte `json:"new_password"`
		}
		_ = ipc.DecodeBody(ipc.BodyReq, env, &pw)
		f.lastOldPw, f.lastNewPw = pw.Old, pw.New
		return mk(ipc.VaultPasswdResp{})
	case ipc.OpRename, ipc.OpProjectCreate, ipc.OpEnvCreate:
		return mk(struct{}{})
	case ipc.OpBynWrite:
		var pw struct {
			Password []byte `json:"password"`
		}
		_ = ipc.DecodeBody(ipc.BodyReq, env, &pw)
		f.lastPassword = pw.Password
		trusted := len(pw.Password) > 0
		resp := ipc.BynWriteResp{Path: "/proj/.byn", Trusted: trusted}
		if trusted {
			resp.Actions = []string{"make test"}
			resp.Auth = map[string]string{"get": "none"}
		}
		return mk(resp)
	case ipc.OpFSListDir:
		return mk(ipc.ListDirResp{Path: "/home/u", Parent: "/home", Entries: []ipc.DirEntry{{Name: "proj"}}})
	case ipc.OpAuditTail:
		return mk(ipc.AuditTailResp{Events: []ipc.AuditEvent{
			{Op: "get", Outcome: "ok", EntryName: "API_KEY", CallerComm: "byn", CallerSurface: "socket", TS: 1},
		}})
	case ipc.OpAuditVerify:
		return mk(ipc.AuditVerifyResp{Total: 1, BadIndex: -1})
	case ipc.OpTrustList:
		return mk(ipc.TrustListResp{Entries: []ipc.TrustEntry{{Path: "/proj/.byn", SHA256: "deadbeef"}}})
	case ipc.OpTrustRemove:
		return mk(ipc.TrustRemoveResp{Removed: true})
	case ipc.OpPasskeyRegisterBegin:
		return mk(ipc.PasskeyRegisterBeginResp{CeremonyID: "creg", Options: json.RawMessage(`{"publicKey":{"challenge":"AA"}}`)})
	case ipc.OpPasskeyRegisterFinish:
		return mk(ipc.PasskeyRegisterFinishResp{CredentialID: []byte{1, 2}, Label: "Touch ID"})
	case ipc.OpPasskeyAuthBegin:
		return mk(ipc.PasskeyAuthBeginResp{CeremonyID: "cauth", Options: json.RawMessage(`{"publicKey":{"challenge":"BB"}}`)})
	case ipc.OpPasskeyAuthFinish:
		if f.wrongPassword {
			return ipc.NewError(env.ID, ipc.CodeWrongPassword, "passkey sign-in failed", "")
		}
		return mk(ipc.PasskeyAuthFinishResp{CredentialID: []byte{1, 2}})
	case ipc.OpPasskeyList:
		return mk(ipc.PasskeyListResp{Passkeys: []ipc.PasskeyInfo{{CredentialID: []byte{1, 2}, Label: "Touch ID", CreatedAt: 1}}})
	case ipc.OpPasskeyRemove:
		return mk(ipc.PasskeyRemoveResp{Removed: true})
	default:
		return ipc.NewError(env.ID, ipc.CodeUnknownOp, "unknown op", "")
	}
}

// newTestServer returns a portal whose Origin check expects port 2967
// (the default), independent of the random httptest port.
func newTestServer(t *testing.T, f *fakeDisp) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := New(f, Config{Port: 0}) // port 0 ⇒ default 2967 for originAllowed
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return ts, &http.Client{}
}

func getURL(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// post sends a JSON body. origin, when non-empty, sets the Origin header.
func post(t *testing.T, c *http.Client, url, origin string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func TestStatus_Public(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/status")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var s ipc.StatusResp
	_ = json.NewDecoder(resp.Body).Decode(&s)
	if len(s.Vaults) != 1 {
		t.Errorf("unexpected vaults: %+v", s.Vaults)
	}
}

func TestEntries_List_Public(t *testing.T) {
	// No login: listing entry names works without unlocking.
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/entries?vault=default&project=default&env=default")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entries list = %d, want 200 (names are public)", resp.StatusCode)
	}
}

func TestUnlock_WrongPassword(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{wrongPassword: true})
	resp := post(t, c, ts.URL+"/api/unlock", "", map[string]string{"vault": "default", "password": "bad"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-password unlock = %d, want 401", resp.StatusCode)
	}
}

func TestUnlock_OK(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/unlock", "", map[string]string{"vault": "default", "password": "pw"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unlock = %d, want 200", resp.StatusCode)
	}
}

func TestReveal_ReturnsValue(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{revealValue: "s3cr3t"})
	resp := post(t, c, ts.URL+"/api/entry/reveal", "", map[string]any{
		"scope": map[string]string{"vault": "default"}, "name": "API_KEY",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Value != "s3cr3t" {
		t.Errorf("reveal value = %q, want s3cr3t", out.Value)
	}
}

func TestPut_OK(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/entries", "", map[string]any{
		"scope": map[string]string{"vault": "default"}, "name": "X", "value": "y",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put = %d, want 200", resp.StatusCode)
	}
}

func TestPut_CreateOnly_DuplicateErrors(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{dupOnCreate: true})
	resp := post(t, c, ts.URL+"/api/entries", "", map[string]any{
		"scope": map[string]string{"vault": "default"}, "name": "API_KEY", "value": "y", "create_only": true,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("create-only duplicate = %d, want 409", resp.StatusCode)
	}
}

func TestSameOrigin_RejectsCrossOrigin(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/entry/delete", "http://evil.example", map[string]any{
		"scope": map[string]string{"vault": "default"}, "name": "API_KEY",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST = %d, want 403", resp.StatusCode)
	}
}

func TestSameOrigin_AllowsMatchingOrigin(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/entry/delete", "http://localhost:2967", map[string]any{
		"scope": map[string]string{"vault": "default"}, "name": "API_KEY",
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("matching-origin POST = %d, want 200", resp.StatusCode)
	}
}

func TestVaultCreate(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/vaults", "", map[string]string{"name": "work", "password": "pw"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vault create = %d, want 200", resp.StatusCode)
	}
}

func TestScope_CreateDelete(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	cases := []struct {
		path string
		body any
	}{
		{"/api/projects", map[string]string{"vault": "v", "name": "p"}},
		{"/api/envs", map[string]string{"vault": "v", "project": "p", "name": "e"}},
		{"/api/project/delete", map[string]string{"vault": "v", "name": "p"}},
		{"/api/env/delete", map[string]string{"vault": "v", "project": "p", "name": "e"}},
		{"/api/vault/delete", map[string]string{"name": "v"}},
	}
	for _, tc := range cases {
		resp := post(t, c, ts.URL+tc.path, "", tc.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST %s = %d, want 200", tc.path, resp.StatusCode)
		}
	}
}

// Each delete endpoint forwards the authorizing password to the daemon, so
// a locked vault can be mutated without unlocking.
func TestDeletes_ForwardPassword(t *testing.T) {
	cases := []struct {
		path string
		body map[string]any
	}{
		{"/api/entry/delete", map[string]any{"scope": map[string]string{"vault": "v"}, "name": "K", "password": "pw-entry"}},
		{"/api/project/delete", map[string]any{"vault": "v", "name": "p", "password": "pw-proj"}},
		{"/api/env/delete", map[string]any{"vault": "v", "project": "p", "name": "e", "password": "pw-env"}},
		{"/api/vault/delete", map[string]any{"name": "acme", "password": "pw-vault"}},
	}
	for _, tc := range cases {
		f := &fakeDisp{}
		ts, c := newTestServer(t, f)
		resp := post(t, c, ts.URL+tc.path, "http://localhost:2967", tc.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST %s = %d, want 200", tc.path, resp.StatusCode)
			continue
		}
		want := tc.body["password"].(string)
		if got := string(f.lastPassword); got != want {
			t.Errorf("POST %s forwarded password %q, want %q", tc.path, got, want)
		}
	}
}

func TestVaultPasswd_ForwardsPasswords(t *testing.T) {
	f := &fakeDisp{}
	ts, c := newTestServer(t, f)
	resp := post(t, c, ts.URL+"/api/vault/passwd", "http://localhost:2967",
		map[string]any{"vault": "work", "old_password": "old-pw", "new_password": "new-pw"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(f.lastOldPw) != "old-pw" || string(f.lastNewPw) != "new-pw" {
		t.Errorf("forwarded (%q,%q), want (old-pw,new-pw)", f.lastOldPw, f.lastNewPw)
	}
}

func TestRenames_Reach(t *testing.T) {
	cases := []struct {
		path string
		body map[string]any
	}{
		{"/api/project/rename", map[string]any{"vault": "v", "old_name": "p", "new_name": "p2"}},
		{"/api/env/rename", map[string]any{"vault": "v", "project": "p", "old_name": "e", "new_name": "e2"}},
		{"/api/vault/rename", map[string]any{"old_name": "acme", "new_name": "brand"}},
	}
	for _, tc := range cases {
		ts, c := newTestServer(t, &fakeDisp{})
		resp := post(t, c, ts.URL+tc.path, "http://localhost:2967", tc.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST %s = %d, want 200", tc.path, resp.StatusCode)
		}
	}
}

func TestVaultRename_ForwardsPassword(t *testing.T) {
	f := &fakeDisp{}
	ts, c := newTestServer(t, f)
	resp := post(t, c, ts.URL+"/api/vault/rename", "http://localhost:2967",
		map[string]any{"old_name": "acme", "new_name": "brand", "password": "rename-pw"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(f.lastPassword) != "rename-pw" {
		t.Errorf("forwarded password = %q, want rename-pw", f.lastPassword)
	}
}

func TestBynWrite_ReachAndForwardsPassword(t *testing.T) {
	f := &fakeDisp{}
	ts, c := newTestServer(t, f)
	resp := post(t, c, ts.URL+"/api/byn/write", "http://localhost:2967",
		map[string]any{
			"dir":      "/tmp/proj",
			"scope":    map[string]any{"vault": "default", "project": "p"},
			"env_vars": []string{"A", "B"},
			"trust":    true,
			"password": "byn-pw",
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(f.lastPassword) != "byn-pw" {
		t.Errorf("forwarded password = %q, want byn-pw", f.lastPassword)
	}
	var got struct {
		Path    string            `json:"path"`
		Trusted bool              `json:"trusted"`
		Actions []string          `json:"actions"`
		Auth    map[string]string `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Path != "/proj/.byn" || !got.Trusted {
		t.Errorf("resp = %+v, want path=/proj/.byn trusted=true", got)
	}
	// Policy fields must be passed through when trusted.
	if len(got.Actions) != 1 || got.Actions[0] != "make test" {
		t.Errorf("Actions = %v, want [make test]", got.Actions)
	}
	if got.Auth["get"] != "none" {
		t.Errorf("Auth = %v, want {get:none}", got.Auth)
	}
}

func TestFSListDir_Reach(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := getURL(t, c, ts.URL+"/api/fs/listdir?path=/home/u")
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.StatusCode)
	}
	var resp ipc.ListDirResp
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Path != "/home/u" || len(resp.Entries) != 1 || resp.Entries[0].Name != "proj" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestAuditAndTrust_Endpoints(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	// audit list
	r1 := getURL(t, c, ts.URL+"/api/audit?vault=default&n=10")
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit = %d", r1.StatusCode)
	}
	var ar ipc.AuditTailResp
	if err := json.NewDecoder(r1.Body).Decode(&ar); err != nil {
		t.Fatal(err)
	}
	if len(ar.Events) != 1 || ar.Events[0].Op != "get" {
		t.Fatalf("audit events = %+v", ar.Events)
	}
	// audit verify
	r2 := getURL(t, c, ts.URL+"/api/audit/verify?vault=default")
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/audit/verify = %d", r2.StatusCode)
	}
	// trust list
	r3 := getURL(t, c, ts.URL+"/api/trust")
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/trust = %d", r3.StatusCode)
	}
	var tr ipc.TrustListResp
	if err := json.NewDecoder(r3.Body).Decode(&tr); err != nil {
		t.Fatal(err)
	}
	if len(tr.Entries) != 1 || tr.Entries[0].Path != "/proj/.byn" {
		t.Fatalf("trust entries = %+v", tr.Entries)
	}
	// trust revoke
	r4 := post(t, c, ts.URL+"/api/trust/remove", "http://localhost:2967", map[string]any{"path": "/proj/.byn"})
	defer r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/trust/remove = %d", r4.StatusCode)
	}
}

func TestIndex_Served(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index content-type = %q, want text/html", ct)
	}
}

func TestUnknownPath_404(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/nope")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", resp.StatusCode)
	}
}

// ---- per_action_auth portal tests ----------------------------------------
//
// These tests confirm the portal HTTP surface honours the auth_required gate
// introduced by [security] per_action_auth. They use a canned dispatcher
// (perActionDisp) that mimics the daemon gate: it returns auth_required unless
// the request body carries a non-empty password or a valid single-use
// presence_token, and supplies a mint() helper the test can use to produce a
// token — so no real daemon or vault is needed.
//
// Coverage:
//   (a) reveal/get without creds → 401 auth_required
//   (b) reveal/get with password  → 200
//   (c) reveal/get with presence_token → 200
//   (d) presence_token reuse → 401 auth_required (single-use enforced)

const testVault = "default"
const testPassword = "correct-horse"

// perActionDisp is a fakeDisp variant that gates OpGet and OpPut-overwrite
// behind an auth check, mirrors what the real daemon does for per_action_auth.
type perActionDisp struct {
	fakeDisp
	// usedTokens tracks consumed presence tokens (single-use enforcement).
	usedTokens map[string]struct{}
}

func newPerActionDisp(revealValue string) *perActionDisp {
	return &perActionDisp{
		fakeDisp:   fakeDisp{revealValue: revealValue},
		usedTokens: make(map[string]struct{}),
	}
}

// mint creates a test presence token and stores it in the dispatcher so the
// first use succeeds but any replay fails.
func (d *perActionDisp) mint() []byte {
	tok := []byte("test-presence-token-" + string(rune(len(d.usedTokens)+65)))
	return tok
}

func (d *perActionDisp) Dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	switch env.Op {
	case ipc.OpGet:
		var req ipc.GetReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		if err := d.checkAuth(env.ID, req.Password, req.PresenceToken); err != nil {
			return err
		}
		resp, _ := ipc.NewResponse(env.ID, ipc.GetResp{Name: req.Name, Value: []byte(d.revealValue), Source: "scope"})
		return resp
	case ipc.OpPut:
		var req ipc.PutReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		if !req.CreateOnly {
			// Overwrite path needs auth (same as daemon).
			if err := d.checkAuth(env.ID, req.Password, req.PresenceToken); err != nil {
				return err
			}
		}
		resp, _ := ipc.NewResponse(env.ID, ipc.PutResp{})
		return resp
	case ipc.OpVaultRename:
		var req ipc.VaultRenameReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		if err := d.checkAuth(env.ID, req.Password, req.PresenceToken); err != nil {
			return err
		}
		d.lastPassword = req.Password
		resp, _ := ipc.NewResponse(env.ID, ipc.VaultRenameResp{})
		return resp
	default:
		return d.fakeDisp.Dispatch(ctx, env)
	}
}

// checkAuth returns an auth_required error envelope when neither a valid
// password nor a valid (unconsumed) presence token is provided.
func (d *perActionDisp) checkAuth(id string, password, presenceToken []byte) *ipc.Envelope {
	if len(presenceToken) > 0 {
		key := string(presenceToken)
		if _, used := d.usedTokens[key]; used {
			return ipc.NewError(id, ipc.CodeAuthRequired, "passkey authorization expired or invalid", "re-authenticate")
		}
		// Mark as consumed (single-use).
		d.usedTokens[key] = struct{}{}
		return nil // valid, first use
	}
	if len(password) > 0 && string(password) == testPassword {
		return nil // correct password
	}
	if len(password) > 0 {
		// Non-empty but wrong password → wrong_password, not auth_required.
		return ipc.NewError(id, ipc.CodeWrongPassword, "wrong password", "")
	}
	return ipc.NewError(id, ipc.CodeAuthRequired, "this action requires authorization ([security] per_action_auth)", "supply password")
}

// TestReveal_AuthRequired_NoCreds: reveal without password/token → 401.
func TestReveal_AuthRequired_NoCreds(t *testing.T) {
	d := newPerActionDisp("secret")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reveal without creds = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != string(ipc.CodeAuthRequired) {
		t.Errorf("code = %q, want auth_required", body["code"])
	}
}

// TestReveal_AuthRequired_WithPassword: reveal with correct password → 200.
func TestReveal_AuthRequired_WithPassword(t *testing.T) {
	d := newPerActionDisp("s3cr3t")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY", "password": testPassword})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal with password = %d, want 200", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["value"] != "s3cr3t" {
		t.Errorf("value = %q, want s3cr3t", out["value"])
	}
}

// TestReveal_AuthRequired_WithPresenceToken: reveal with a fresh token → 200.
func TestReveal_AuthRequired_WithPresenceToken(t *testing.T) {
	d := newPerActionDisp("tok-val")
	ts, c := newTestServerWith(t, d)

	tok := d.mint()
	resp := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY", "presence_token": tok})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal with token = %d, want 200", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["value"] != "tok-val" {
		t.Errorf("value = %q, want tok-val", out["value"])
	}
}

// TestReveal_AuthRequired_TokenReuse: a token used twice → 401 on the second call.
func TestReveal_AuthRequired_TokenReuse(t *testing.T) {
	d := newPerActionDisp("secret")
	ts, c := newTestServerWith(t, d)

	tok := d.mint()
	// First use — should succeed.
	r1 := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY", "presence_token": tok})
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first reveal = %d, want 200", r1.StatusCode)
	}
	// Second use (replay) — must be rejected.
	r2 := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY", "presence_token": tok})
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token replay = %d, want 401", r2.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(r2.Body).Decode(&body)
	if body["code"] != string(ipc.CodeAuthRequired) {
		t.Errorf("code = %q, want auth_required", body["code"])
	}
}

// TestPut_AuthRequired_Overwrite_NoCreds: overwrite put without creds → 401.
func TestPut_AuthRequired_Overwrite_NoCreds(t *testing.T) {
	d := newPerActionDisp("")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/entries", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "X", "value": "new"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("overwrite put without creds = %d, want 401", resp.StatusCode)
	}
}

// TestPut_AuthRequired_Overwrite_WithPassword: overwrite with password → 200.
func TestPut_AuthRequired_Overwrite_WithPassword(t *testing.T) {
	d := newPerActionDisp("")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/entries", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "X", "value": "new", "password": testPassword})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overwrite put with password = %d, want 200", resp.StatusCode)
	}
}

// newTestServerWith creates a test server using any Dispatcher (not just *fakeDisp).
func newTestServerWith(t *testing.T, d Dispatcher) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := New(d, Config{Port: 0})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return ts, &http.Client{}
}

// capDisp satisfies Dispatcher and captures the last PresenceToken sent to OpGet.
type capDisp struct {
	fakeDisp
	lastPresenceToken []byte
}

func (d *capDisp) Dispatch(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	if env.Op == ipc.OpGet {
		var req ipc.GetReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		d.lastPresenceToken = req.PresenceToken
	}
	return d.fakeDisp.Dispatch(ctx, env)
}

// TestReveal_ForwardsPresenceTokenIPC checks that the portal's HTTP handler
// deserialises presence_token from the JSON body and includes it in the IPC
// GetReq sent to the dispatcher.
func TestReveal_ForwardsPresenceTokenIPC(t *testing.T) {
	d := &capDisp{fakeDisp: fakeDisp{revealValue: "captured"}}
	ts, c := newTestServerWith(t, d)

	tok := []byte("forward-me-token")
	resp := post(t, c, ts.URL+"/api/entry/reveal", "",
		map[string]any{"scope": map[string]string{"vault": testVault}, "name": "API_KEY", "presence_token": tok})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal = %d, want 200", resp.StatusCode)
	}
	if string(d.lastPresenceToken) != string(tok) {
		t.Errorf("IPC presence_token = %q, want %q", d.lastPresenceToken, tok)
	}
}

// ---- vault rename per_action_auth step-up --------------------------------

// TestVaultRename_AuthRequired_NoCreds: /api/vault/rename without password or
// presence_token when [security] per_action_auth is on → 401 auth_required.
func TestVaultRename_AuthRequired_NoCreds(t *testing.T) {
	d := newPerActionDisp("")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/vault/rename", "http://localhost:2967",
		map[string]any{"old_name": "acme", "new_name": "brand"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("vault rename without creds = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != string(ipc.CodeAuthRequired) {
		t.Errorf("code = %q, want auth_required", body["code"])
	}
}

// TestVaultRename_AuthRequired_WithPassword: /api/vault/rename with correct
// password when gated → 200.
func TestVaultRename_AuthRequired_WithPassword(t *testing.T) {
	d := newPerActionDisp("")
	ts, c := newTestServerWith(t, d)

	resp := post(t, c, ts.URL+"/api/vault/rename", "http://localhost:2967",
		map[string]any{"old_name": "acme", "new_name": "brand", "password": testPassword})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vault rename with password = %d, want 200", resp.StatusCode)
	}
}

// TestVaultRename_ForwardsPresenceToken: the portal passes presence_token
// through to the IPC VaultRenameReq.
func TestVaultRename_ForwardsPresenceToken(t *testing.T) {
	d := newPerActionDisp("")
	ts, c := newTestServerWith(t, d)

	tok := d.mint()
	resp := post(t, c, ts.URL+"/api/vault/rename", "http://localhost:2967",
		map[string]any{"old_name": "acme", "new_name": "brand", "presence_token": tok})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vault rename with presence_token = %d, want 200", resp.StatusCode)
	}
}
