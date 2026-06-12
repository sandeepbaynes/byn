package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/ui"
)

// freePort returns a currently-free localhost TCP port so the portal e2e
// never collides with a real daemon on the default 2967.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

// TestUI_EndToEnd brings up a real daemon with the embedded portal, seeds
// a vault over the socket, then drives the browser API over HTTP. The
// portal has no login: listing/reveal work while the vault is unlocked,
// and a lock from the portal makes value reads fail with 423.
//
// NU-3 session threading: the vault is initialised via the raw IPC socket
// (cheap: no session needed for init/put) but unlocked via the portal
// HTTP API so the portal server can capture the minted session token.
// Subsequent reveal/add calls work without supplying a password because
// the portal threads the session token transparently via callInVault.
func TestUI_EndToEnd(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test", UIEnabled: true, UIPort: freePort(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { cancel(); d.Shutdown(2 * time.Second) })

	port := d.UIPort()
	if port == 0 {
		t.Fatal("portal did not start (UIPort == 0)")
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Init and seed the vault over the raw IPC socket.
	// Init and put are always-free or session-satisfiable ops; they don't
	// need the portal session path.  We unlock via socket just to do the
	// initial put, then re-lock so the portal unlock below is the canonical
	// session source.
	c := ipc.NewClient(d.SocketPath())
	pw := []byte("correct-horse")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("socket-unlock for put: %v", err)
	}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "API_KEY", Value: []byte("s3cret-value")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Re-lock so the portal unlock below is the canonical session source.
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{Name: "default"}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("socket-lock: %v", err)
	}

	// Read the portal owner-token that the daemon wrote on start. Every HTTP
	// request to /api/* must carry this token.
	tokenPath := filepath.Join(dir, ui.TokenFilename)
	portalToken, err := ui.LoadOrCreateToken(tokenPath)
	if err != nil {
		t.Fatalf("read portal token: %v", err)
	}

	hc := &http.Client{Timeout: 5 * time.Second}
	// withToken builds a request with the owner-token header pre-set.
	withToken := func(method, path string, body []byte) *http.Request {
		var bodyReader *bytes.Reader
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
		} else {
			bodyReader = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, base+path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Byn-Portal-Token", portalToken)
		return req
	}
	post := func(path string, body any) *http.Response {
		b, _ := json.Marshal(body)
		resp, err := hc.Do(withToken(http.MethodPost, path, b))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	// Unlock via the portal HTTP API so the server captures the session token.
	// From this point on, reveal/add no longer need a password supplied in the
	// request body — the portal threads the captured token transparently.
	ulk := post("/api/unlock", map[string]string{"vault": "default", "password": "correct-horse"})
	if ulk.StatusCode != http.StatusOK {
		t.Fatalf("portal unlock = %d, want 200", ulk.StatusCode)
	}
	ulk.Body.Close()

	// List entries — the seeded API_KEY must be visible (token gate must pass).
	lr, err := hc.Do(withToken(http.MethodGet, "/api/entries?vault=default&project=default&env=default", nil))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var list ipc.ListResp
	_ = json.NewDecoder(lr.Body).Decode(&list)
	lr.Body.Close()
	found := false
	for _, s := range list.Secrets {
		if s.Name == "API_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatalf("API_KEY not in portal list: %+v", list.Secrets)
	}

	// Reveal — value read works while the vault is unlocked AND the portal
	// has the session token.  No password is supplied in the request body;
	// the portal threads the session transparently via callInVault.
	rv := post("/api/entry/reveal", map[string]any{
		"scope": map[string]string{"vault": "default", "project": "default", "env": "default"},
		"name":  "API_KEY",
	})
	if rv.StatusCode != http.StatusOK {
		t.Fatalf("reveal = %d, want 200", rv.StatusCode)
	}
	var revealed struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(rv.Body).Decode(&revealed)
	rv.Body.Close()
	if revealed.Value != "s3cret-value" {
		t.Fatalf("reveal value = %q, want s3cret-value", revealed.Value)
	}

	// Add via HTTP, confirm it round-trips through the real vault.
	add := post("/api/entries", map[string]any{
		"scope": map[string]string{"vault": "default", "project": "default", "env": "default"},
		"name":  "DB_URL",
		"value": "postgres://x",
	})
	if add.StatusCode != http.StatusOK {
		t.Fatalf("http add = %d, want 200", add.StatusCode)
	}
	add.Body.Close()
	// Verify round-trip over the raw socket.  The socket client c has no
	// session token (it pre-dates the portal unlock), so supply the password
	// as a one-shot credential — this is a test-only read, not a user flow.
	var got ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "DB_URL", Password: pw}, &got); err != nil {
		t.Fatalf("get DB_URL via socket: %v", err)
	}
	if string(got.Value) != "postgres://x" {
		t.Fatalf("DB_URL via socket = %q, want postgres://x", string(got.Value))
	}

	// Lock the vault from the portal.  After lock the portal also clears its
	// in-memory session token, so subsequent reveal calls have neither a
	// session nor a password — the daemon returns 401 (auth_required) rather
	// than 423 (locked), because the NU-3 session gate fires before the vault
	// lock check.  The browser's apiWithAuth handles 401 by showing the unlock
	// dialog, which is the correct UX: "you need to re-authenticate".
	lk := post("/api/lock", map[string]string{"vault": "default"})
	if lk.StatusCode != http.StatusOK {
		t.Fatalf("http lock = %d, want 200", lk.StatusCode)
	}
	lk.Body.Close()
	after := post("/api/entry/reveal", map[string]any{
		"scope": map[string]string{"vault": "default", "project": "default", "env": "default"},
		"name":  "API_KEY",
	})
	after.Body.Close()
	// After lock + session cleared: auth_required (401) — the session gate
	// fires before the vault-locked gate; the browser triggers re-unlock.
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reveal after lock = %d, want 401 (auth_required — re-unlock needed)", after.StatusCode)
	}
}
