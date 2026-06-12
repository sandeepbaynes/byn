package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// fakeDisp is a canned Dispatcher for handler tests.
type fakeDisp struct {
	wrongPassword     bool
	revealValue       string
	dupOnCreate       bool   // OpPut with CreateOnly → already_exists
	lastPassword      []byte // password decoded from the last delete-family op
	lastOldPw         []byte // old_password from the last passwd op
	lastNewPw         []byte // new_password from the last passwd op
	lastBynContent    []byte // content bytes from the last OpBynWrite request
	lastConfigContent []byte // content bytes from the last OpConfigSet request
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
		var req ipc.BynWriteReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		f.lastPassword = req.Password
		f.lastBynContent = req.Content
		trusted := len(req.Password) > 0
		resp := ipc.BynWriteResp{Path: "/proj/.byn", Trusted: trusted}
		if trusted {
			resp.Actions = []string{"make test"}
			resp.Auth = map[string]string{"get": "none"}
		}
		return mk(resp)
	case ipc.OpFSListDir:
		return mk(ipc.ListDirResp{Path: "/home/u", Parent: "/home", Entries: []ipc.DirEntry{{Name: "proj"}}})
	case ipc.OpBynValidate:
		var req ipc.BynValidateReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		// Return an error issue when content contains "BADKEY" (test sentinel).
		if bytes.Contains(req.Content, []byte("BADKEY")) {
			return mk(ipc.BynValidateResp{Errors: []ipc.BynIssue{{Section: "toml", Message: "unknown key: BADKEY"}}})
		}
		return mk(ipc.BynValidateResp{})
	case ipc.OpBynSimulate:
		var req ipc.BynSimulateReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		return mk(ipc.BynSimulateResp{
			ResolvedArgv:  strings.Fields(req.CommandLine),
			MatchedKind:   "action",
			MatchedAction: "make test",
			Verdict:       "free",
			Reason:        "matched action",
		})
	case ipc.OpBynRead:
		var req ipc.BynReadReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		parsed := &ipc.BynParsed{}
		parsed.Scope.Vault = "default"
		parsed.Env = []string{"API_KEY"}
		parsed.Actions = []string{"make test"}
		return mk(ipc.BynReadResp{
			Path:        req.Path,
			Content:     []byte("[scope]\nvault=\"default\"\n"),
			TrustStatus: "trusted",
			Parsed:      parsed,
		})
	case ipc.OpConfigGet:
		return mk(ipc.ConfigGetResp{
			Path:    "/home/u/.byn/config",
			Content: []byte("[ui]\nport = 2967\n"),
			Parsed: &ipc.ConfigParsed{
				UIEnabled:   true,
				UIPort:      2967,
				IdleTimeout: "15m0s",
			},
		})
	case ipc.OpConfigSet:
		var req ipc.ConfigSetReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		f.lastConfigContent = req.Content
		if f.wrongPassword && len(req.Password) > 0 {
			return ipc.NewError(env.ID, ipc.CodeWrongPassword, "wrong password", "verify password")
		}
		if len(req.Password) == 0 && len(req.PresenceToken) == 0 {
			return ipc.NewError(env.ID, ipc.CodeAuthRequired, "config change requires authorization", "supply password")
		}
		return mk(ipc.ConfigSetResp{ChangeNotes: []string{"[ui] port unchanged", "[daemon] idle_timeout applied"}})
	case ipc.OpConfigValidate:
		var req ipc.ConfigValidateReq
		_ = ipc.DecodeBody(ipc.BodyReq, env, &req)
		// Return an error issue when content contains "BADTOML" (test sentinel).
		if bytes.Contains(req.Content, []byte("BADTOML")) {
			return mk(ipc.ConfigValidateResp{Errors: []ipc.BynIssue{{Section: "toml", Message: "unexpected toml error"}}})
		}
		return mk(ipc.ConfigValidateResp{
			Parsed: &ipc.ConfigParsed{
				UIEnabled:   true,
				UIPort:      2967,
				IdleTimeout: "15m0s",
			},
		})
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
	case ipc.OpDaemonReload:
		return mk(ipc.DaemonReloadResp{ChangeNotes: []string{"idle_timeout disabled → 5m0s"}})
	case ipc.OpDaemonRestart:
		return mk(ipc.DaemonRestartResp{Message: "daemon stopping — use `byn start` to restart"})
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

// TestSPAFallback_AppRoute: non-api GET paths serve index.html (history-API
// fallback) so deep-linked routes reload correctly.
func TestSPAFallback_AppRoute(t *testing.T) {
	for _, path := range []string{"/settings", "/trust", "/audit", "/studio", "/entries/v/p/e", "/nope"} {
		ts, c := newTestServer(t, &fakeDisp{})
		resp := getURL(t, c, ts.URL+path)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (SPA fallback)", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s content-type = %q, want text/html", path, ct)
		}
	}
}

// TestSPAFallback_APIStill404: /api/* paths that don't match a registered
// route must still return 404, not a silently-served HTML page.
func TestSPAFallback_APIStill404(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/nope")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /api/nope = %d, want 404", resp.StatusCode)
	}
}

// TestSPAFallback_StaticAsset: /static/app.js is served as JavaScript, not
// overridden by the SPA fallback.
func TestSPAFallback_StaticAsset(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/static/app.js")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /static/app.js = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("GET /static/app.js content-type = %q, want javascript", ct)
	}
}

// ---- portal auth_required gate tests ----------------------------------------
//
// These tests confirm the portal HTTP surface honours the auth_required gate
// (NU-3 session matrix). They use a canned dispatcher (perActionDisp) that
// mimics the daemon gate: it returns auth_required unless the request body
// carries a non-empty password or a valid single-use presence_token, and
// supplies a mint() helper the test can use to produce a token — so no real
// daemon or vault is needed.
//
// Coverage:
//   (a) reveal/get without creds → 401 auth_required
//   (b) reveal/get with password  → 200
//   (c) reveal/get with presence_token → 200
//   (d) presence_token reuse → 401 auth_required (single-use enforced)

const testVault = "default"
const testPassword = "correct-horse"

// perActionDisp is a fakeDisp variant that gates OpGet and OpPut-overwrite
// behind an auth check, mirrors what the real daemon does for the NU-3 gate.
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
	return ipc.NewError(id, ipc.CodeAuthRequired, "this action requires authorization", "supply password")
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

// ---- vault rename auth_required gate --------------------------------

// TestVaultRename_AuthRequired_NoCreds: /api/vault/rename without password or
// presence_token → 401 auth_required.
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

// ---- .byn studio route tests -----------------------------------------------

// TestBynValidate_OK: valid content returns 200 with no errors.
func TestBynValidate_OK(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/byn/validate", "http://localhost:2967",
		map[string]string{"content": "[scope]\nvault=\"default\"\n"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("byn/validate ok = %d, want 200", resp.StatusCode)
	}
	var out ipc.BynValidateResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) != 0 {
		t.Errorf("unexpected errors: %v", out.Errors)
	}
}

// TestBynValidate_BadContent: content with BADKEY sentinel returns errors.
func TestBynValidate_BadContent(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/byn/validate", "http://localhost:2967",
		map[string]string{"content": "[scope]\nBADKEY=\"x\"\n"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("byn/validate bad content = %d, want 200 with errors in body", resp.StatusCode)
	}
	var out ipc.BynValidateResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) == 0 {
		t.Error("expected errors for bad content, got none")
	}
	if out.Errors[0].Section != "toml" {
		t.Errorf("section = %q, want toml", out.Errors[0].Section)
	}
}

// TestBynValidate_CSRF: cross-origin POST must be rejected.
func TestBynValidate_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/byn/validate", "http://evil.example",
		map[string]string{"content": "[scope]\n"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin byn/validate = %d, want 403", resp.StatusCode)
	}
}

// TestBynSimulate_ReturnsVerdict: simulate returns a verdict from the daemon.
func TestBynSimulate_ReturnsVerdict(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/byn/simulate", "http://localhost:2967",
		map[string]string{"content": "[exec]\nactions=[\"make test\"]\n", "command_line": "make test"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("byn/simulate = %d, want 200", resp.StatusCode)
	}
	var out ipc.BynSimulateResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Verdict != "free" {
		t.Errorf("verdict = %q, want free", out.Verdict)
	}
	if out.MatchedKind != "action" {
		t.Errorf("matched_kind = %q, want action", out.MatchedKind)
	}
}

// TestBynSimulate_CSRF: cross-origin POST must be rejected.
func TestBynSimulate_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/byn/simulate", "http://evil.example",
		map[string]string{"content": "[exec]\n", "command_line": "make"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin byn/simulate = %d, want 403", resp.StatusCode)
	}
}

// TestBynRead_ReturnsContentAndStatus: POST byn/read returns the file content
// and trust status.
func TestBynRead_ReturnsContentAndStatus(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/byn/read", "http://localhost:2967",
		map[string]string{"path": "/proj/.byn"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("byn/read = %d, want 200", r.StatusCode)
	}
	var out struct {
		Path        string `json:"path"`
		Content     string `json:"content"`
		TrustStatus string `json:"trust_status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Path != "/proj/.byn" {
		t.Errorf("path = %q, want /proj/.byn", out.Path)
	}
	if out.TrustStatus != "trusted" {
		t.Errorf("trust_status = %q, want trusted", out.TrustStatus)
	}
	if out.Content == "" {
		t.Error("content must not be empty")
	}
}

// TestBynRead_CSRF: cross-origin POST to byn/read must be rejected by sameOrigin.
func TestBynRead_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/byn/read", "http://evil.example",
		map[string]string{"path": "/proj/.byn"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST byn/read = %d, want 403", r.StatusCode)
	}
}

// TestBynRead_MethodNotAllowed: GET to byn/read must return 405 (route is POST-only).
func TestBynRead_MethodNotAllowed(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/byn/read?path=/proj/.byn")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET byn/read = %d, want 405", resp.StatusCode)
	}
}

// TestBynWrite_ContentFieldForwarded: the portal handler forwards the content
// field from the JSON body to the IPC BynWriteReq.Content bytes.
func TestBynWrite_ContentFieldForwarded(t *testing.T) {
	f := &fakeDisp{}
	ts, c := newTestServer(t, f)
	const wantContent = "[scope]\nvault=\"acme\"\n"
	resp := post(t, c, ts.URL+"/api/byn/write", "http://localhost:2967",
		map[string]any{
			"dir":     "/tmp/proj",
			"content": wantContent,
			"trust":   false,
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(f.lastBynContent) != wantContent {
		t.Errorf("IPC content = %q, want %q", f.lastBynContent, wantContent)
	}
}

// ---- /api/config tests -------------------------------------------------------

// TestConfigGet_ReturnsContent: GET /api/config returns path, content, and parsed.
func TestConfigGet_ReturnsContent(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := getURL(t, c, ts.URL+"/api/config")
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/config = %d, want 200", r.StatusCode)
	}
	var out struct {
		Path    string            `json:"path"`
		Content string            `json:"content"`
		Parsed  *ipc.ConfigParsed `json:"parsed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Path == "" {
		t.Error("config path must not be empty")
	}
	if out.Content == "" {
		t.Error("config content must not be empty (fakeDisp seeds it)")
	}
	if out.Parsed == nil {
		t.Fatal("parsed must be present when config parses successfully")
	}
	if out.Parsed.UIPort != 2967 {
		t.Errorf("parsed.ui_port = %d, want 2967", out.Parsed.UIPort)
	}
	if out.Parsed.IdleTimeout != "15m0s" {
		t.Errorf("parsed.idle_timeout = %q, want %q", out.Parsed.IdleTimeout, "15m0s")
	}
}

// TestConfigSet_AuthRequired_NoCreds: POST without password or presence_token →
// the daemon returns auth_required → 401.
func TestConfigSet_AuthRequired_NoCreds(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/config", "http://localhost:2967",
		map[string]string{"content": "[ui]\nport = 2967\n"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("config set without creds = %d, want 401", r.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body["code"] != string(ipc.CodeAuthRequired) {
		t.Errorf("code = %q, want auth_required", body["code"])
	}
}

// TestConfigSet_ForwardsContent: POST with password returns 200 and the daemon
// receives the content bytes.
func TestConfigSet_ForwardsContent(t *testing.T) {
	f := &fakeDisp{}
	ts, c := newTestServer(t, f)
	const wantContent = "[daemon]\nidle_timeout = \"10m\"\n"
	r := post(t, c, ts.URL+"/api/config", "http://localhost:2967",
		map[string]any{"content": wantContent, "password": "correct-horse"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("config set = %d, want 200", r.StatusCode)
	}
	if string(f.lastConfigContent) != wantContent {
		t.Errorf("IPC content = %q, want %q", f.lastConfigContent, wantContent)
	}
	var resp ipc.ConfigSetResp
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ChangeNotes) == 0 {
		t.Error("expected change_notes in response")
	}
}

// TestConfigSet_CSRF: cross-origin POST must be rejected with 403.
func TestConfigSet_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/config", "http://evil.example",
		map[string]string{"content": "[ui]\nport = 2967\n", "password": "pw"})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin config set = %d, want 403", r.StatusCode)
	}
}

// TestConfig_MethodNotAllowed: methods other than GET/POST must return 405.
func TestConfig_MethodNotAllowed(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/config", nil)
	req.Header.Set("Origin", "http://localhost:2967")
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /api/config = %d, want 405", r.StatusCode)
	}
}

// ---- /api/config/validate tests -----------------------------------------------

// TestConfigValidate_ValidContent: POST valid config → 200 with parsed.
func TestConfigValidate_ValidContent(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/config/validate", "http://localhost:2967",
		map[string]string{"content": "[ui]\nport = 2967\n"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("config validate = %d, want 200", r.StatusCode)
	}
	var out ipc.ConfigValidateResp
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) != 0 {
		t.Errorf("expected no errors for valid content; got: %v", out.Errors)
	}
	if out.Parsed == nil {
		t.Fatal("expected parsed to be non-nil for valid content")
	}
	if out.Parsed.UIPort != 2967 {
		t.Errorf("parsed.ui_port = %d, want 2967", out.Parsed.UIPort)
	}
}

// TestConfigValidate_InvalidContent: POST invalid config → 200 with errors, no parsed.
func TestConfigValidate_InvalidContent(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/config/validate", "http://localhost:2967",
		map[string]string{"content": "BADTOML [[["})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("config validate (invalid) = %d, want 200", r.StatusCode)
	}
	var out ipc.ConfigValidateResp
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Errors) == 0 {
		t.Fatal("expected errors for invalid content")
	}
	if out.Errors[0].Section != "toml" {
		t.Errorf("errors[0].section = %q, want \"toml\"", out.Errors[0].Section)
	}
	if out.Parsed != nil {
		t.Error("parsed must be nil when errors are present")
	}
}

// TestConfigValidate_CSRF: cross-origin POST must be rejected with 403.
func TestConfigValidate_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/config/validate", "http://evil.example",
		map[string]string{"content": "[ui]\nport = 2967\n"})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin config validate = %d, want 403", r.StatusCode)
	}
}

// TestConfigValidate_MethodNotAllowed: GET must return 405.
func TestConfigValidate_MethodNotAllowed(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/config/validate")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/config/validate = %d, want 405", resp.StatusCode)
	}
}

// TestBynRead_ParsedFieldPassthrough: byn/read passes through the Parsed
// struct from the daemon response so the studio builder can pre-populate.
func TestBynRead_ParsedFieldPassthrough(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/byn/read", "http://localhost:2967",
		map[string]string{"path": "/proj/.byn"})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("byn/read = %d, want 200", r.StatusCode)
	}
	var out struct {
		Path        string `json:"path"`
		TrustStatus string `json:"trust_status"`
		Parsed      *struct {
			Scope struct {
				Vault string `json:"vault"`
			} `json:"scope"`
			Env     []string `json:"env"`
			Actions []string `json:"actions"`
		} `json:"parsed"`
		ParseError string `json:"parse_error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Parsed == nil {
		t.Fatal("expected parsed field in byn/read response, got nil")
	}
	if out.Parsed.Scope.Vault != "default" {
		t.Errorf("parsed.scope.vault = %q, want \"default\"", out.Parsed.Scope.Vault)
	}
	if len(out.Parsed.Env) != 1 || out.Parsed.Env[0] != "API_KEY" {
		t.Errorf("parsed.env = %v, want [API_KEY]", out.Parsed.Env)
	}
	if len(out.Parsed.Actions) != 1 || out.Parsed.Actions[0] != "make test" {
		t.Errorf("parsed.actions = %v, want [make test]", out.Parsed.Actions)
	}
}

// ---- /api/daemon/reload tests ------------------------------------------

// TestDaemonReload_ReturnsChangeNotes: POST /api/daemon/reload returns 200
// and the change_notes from the daemon.
func TestDaemonReload_ReturnsChangeNotes(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/daemon/reload", "http://localhost:2967", map[string]any{})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/daemon/reload = %d, want 200", r.StatusCode)
	}
	var out ipc.DaemonReloadResp
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.ChangeNotes) == 0 {
		t.Error("expected change_notes in response")
	}
}

// TestDaemonReload_CSRF: cross-origin POST must be rejected with 403.
func TestDaemonReload_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/daemon/reload", "http://evil.example", map[string]any{})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin daemon/reload = %d, want 403", r.StatusCode)
	}
}

// TestDaemonReload_MethodNotAllowed: GET to daemon/reload must return 405.
func TestDaemonReload_MethodNotAllowed(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/daemon/reload")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/daemon/reload = %d, want 405", resp.StatusCode)
	}
}

// ---- /api/daemon/restart tests -----------------------------------------

// TestDaemonRestart_Acknowledges: POST /api/daemon/restart returns 200 with
// a message before the daemon shuts down.
func TestDaemonRestart_Acknowledges(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/daemon/restart", "http://localhost:2967", map[string]any{})
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/daemon/restart = %d, want 200", r.StatusCode)
	}
	var out ipc.DaemonRestartResp
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Message == "" {
		t.Error("expected non-empty message in restart response")
	}
}

// TestDaemonRestart_CSRF: cross-origin POST must be rejected with 403.
func TestDaemonRestart_CSRF(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	r := post(t, c, ts.URL+"/api/daemon/restart", "http://evil.example", map[string]any{})
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin daemon/restart = %d, want 403", r.StatusCode)
	}
}

// TestDaemonRestart_MethodNotAllowed: GET to daemon/restart must return 405.
func TestDaemonRestart_MethodNotAllowed(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/daemon/restart")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/daemon/restart = %d, want 405", resp.StatusCode)
	}
}

// ---- /api/fs/readfile tests ------------------------------------------------

// TestFSReadFile_HappyPath: GET /api/fs/readfile?path=<file> returns 200 and
// the file content in {"content": "..."}.
func TestFSReadFile_HappyPath(t *testing.T) {
	// Write a temp file with known content.
	f, err := os.CreateTemp("", "byn-test-readfile-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	const want = "hello byn\nline2\n"
	if _, err := io.WriteString(f, want); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/fs/readfile?path="+f.Name())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fs/readfile happy path = %d, want 200", resp.StatusCode)
	}
	var out struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Content != want {
		t.Errorf("content = %q, want %q", out.Content, want)
	}
}

// TestFSReadFile_TooLarge: a file exceeding 4 MiB must return 413.
func TestFSReadFile_TooLarge(t *testing.T) {
	f, err := os.CreateTemp("", "byn-test-readfile-large-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	// Write 4 MiB + 1 byte.
	big := make([]byte, (4<<20)+1)
	if _, err := f.Write(big); err != nil {
		t.Fatal(err)
	}
	f.Close()

	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/fs/readfile?path="+f.Name())
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("fs/readfile too large = %d, want 413", resp.StatusCode)
	}
}

// TestFSReadFile_DirectoryRejected: passing a directory path must return 400.
func TestFSReadFile_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()

	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/fs/readfile?path="+dir)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("fs/readfile dir path = %d, want 400", resp.StatusCode)
	}
}

// TestFSReadFile_EmptyPath: omitting the path param must return 400.
func TestFSReadFile_EmptyPath(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/fs/readfile")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("fs/readfile empty path = %d, want 400", resp.StatusCode)
	}
}
