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
