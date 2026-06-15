package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testPortalToken = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

// newGatedTestServer returns a portal configured with testPortalToken so the
// token gate is active. All /api/* requests must carry the token header.
func newGatedTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := New(&fakeDisp{}, Config{Port: 0, Token: testPortalToken})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return ts, &http.Client{}
}

// getWithToken issues a GET request with the portal owner-token header set.
func getWithToken(t *testing.T, c *http.Client, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("X-Byn-Portal-Token", token)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// postWithToken issues a POST request with the portal owner-token header set.
func postWithToken(t *testing.T, c *http.Client, url, token, origin string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Byn-Portal-Token", token)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

// ---- token gate core tests -----------------------------------------------

// TestPortal_ReadOpenNoToken: /api/* reads are OPEN (design A) — no token gate.
// Opening the portal shows status/names with no auth, like `byn ls`.
func TestPortal_ReadOpenNoToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := getWithToken(t, c, ts.URL+"/api/status", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read without token = %d, want 200 (reads are open)", resp.StatusCode)
	}
}

// TestPortal_ReadIgnoresStaleToken: a leftover/garbage token is simply ignored
// now that the gate is gone — reads still succeed.
func TestPortal_ReadIgnoresStaleToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := getWithToken(t, c, ts.URL+"/api/status", "wrongtoken")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read with stale token = %d, want 200 (token ignored)", resp.StatusCode)
	}
}

// TestTokenGate_CorrectToken: /api/* with correct token → 200.
func TestTokenGate_CorrectToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := getWithToken(t, c, ts.URL+"/api/status", testPortalToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("correct token = %d, want 200", resp.StatusCode)
	}
}

// TestPortal_MutationNoTokenProceeds: POST /api/unlock with no token is NOT
// blocked by a token gate (it's gone) — the real gate is the master password the
// daemon enforces. The request reaches the dispatcher (not 401).
func TestPortal_MutationNoTokenProceeds(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/unlock", "", "",
		map[string]string{"vault": "default", "password": "pw"})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("POST /api/unlock without token = 401; a token gate must not exist")
	}
}

// TestTokenGate_PostCorrectToken: POST /api/unlock with correct token → 200.
func TestTokenGate_PostCorrectToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/unlock", testPortalToken, "",
		map[string]string{"vault": "default", "password": "pw"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST with correct token = %d, want 200", resp.StatusCode)
	}
}

// ---- static/SPA ungated tests --------------------------------------------

// TestTokenGate_StaticUngated: /static/app.js does not require a token.
func TestTokenGate_StaticUngated(t *testing.T) {
	ts, c := newGatedTestServer(t)
	// No token header — static assets must serve normally.
	resp, err := c.Get(ts.URL + "/static/app.js")
	if err != nil {
		t.Fatalf("GET /static/app.js: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/static/app.js without token = %d, want 200", resp.StatusCode)
	}
}

// TestTokenGate_IndexUngated: GET / (SPA shell) does not require a token.
func TestTokenGate_IndexUngated(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/ without token = %d, want 200", resp.StatusCode)
	}
}

// TestTokenGate_SPAFallbackUngated: non-api GET paths serve the SPA without
// requiring a token (the HTML is harmless; the API is the boundary).
func TestTokenGate_SPAFallbackUngated(t *testing.T) {
	ts, c := newGatedTestServer(t)
	for _, path := range []string{"/settings", "/trust", "/studio"} {
		resp, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s without token = %d, want 200", path, resp.StatusCode)
		}
	}
}

// ---- token gate + CSRF: both layers must be satisfied -------------------

// TestTokenGate_AndCSRF_BothLayers: a request that has the token but the
// wrong origin must be rejected (403) — the CSRF layer fires after the token
// gate passes.
func TestTokenGate_AndCSRF_BothLayers(t *testing.T) {
	ts, c := newGatedTestServer(t)
	// Correct token, wrong origin → 403 (CSRF wins after token passes).
	resp := postWithToken(t, c, ts.URL+"/api/entry/delete", testPortalToken, "http://evil.example",
		map[string]any{"scope": map[string]string{"vault": "default"}, "name": "K"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("token+wrong-origin = %d, want 403", resp.StatusCode)
	}
}

// TestPortal_MutationNoTokenCorrectOriginProceeds: no token + a same-origin POST
// is accepted (sameOrigin is the CSRF gate; there is no token gate). The daemon's
// per-action password gate is what actually protects the mutation.
func TestPortal_MutationNoTokenCorrectOriginProceeds(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/entry/delete", "", "http://localhost:2967",
		map[string]any{"scope": map[string]string{"vault": "default"}, "name": "K"})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("no-token+correct-origin = 401; there must be no token gate")
	}
}

// TestTokenGate_AndCSRF_BothPass: correct token + correct origin → 200.
func TestTokenGate_AndCSRF_BothPass(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/entry/delete", testPortalToken, "http://localhost:2967",
		map[string]any{"scope": map[string]string{"vault": "default"}, "name": "API_KEY"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token+correct-origin = %d, want 200", resp.StatusCode)
	}
}

// ---- disabled gate (existing behaviour) ----------------------------------

// TestTokenGate_DisabledWhenEmpty: reads are open with no token header.
func TestTokenGate_DisabledWhenEmpty(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/status")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ungated status = %d, want 200", resp.StatusCode)
	}
}

// ---- config-write gate: single-use sudo token (design B) -----------------

// fakeConfigAuth is a test ConfigAuthConsumer that accepts exactly one token value.
type fakeConfigAuth struct{ valid string }

func (f *fakeConfigAuth) ConsumeConfigAuth(t string) bool { return t != "" && t == f.valid }

func newConfigGatedServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := New(&fakeDisp{}, Config{Port: 0, ConfigAuth: &fakeConfigAuth{valid: "goodtoken"}})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return ts, &http.Client{}
}

// TestConfigWrite_RequiresSudoToken: POST /api/config with no X-Byn-Config-Auth
// header → 401 config_auth_required. Config writes are the only portal action
// gated by the single-use sudo token (privsep etc. can't be flipped without it).
func TestConfigWrite_RequiresSudoToken(t *testing.T) {
	ts, c := newConfigGatedServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/config", "", "http://localhost:2967",
		map[string]string{"content": "[ui]\n"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("config write without sudo token = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "config_auth_required" {
		t.Errorf("error = %q, want config_auth_required", body["error"])
	}
}

// TestConfigWrite_WithSudoTokenPassesGate: a valid config-auth token passes the
// gate (the request reaches the dispatcher — not a 401).
func TestConfigWrite_WithSudoTokenPassesGate(t *testing.T) {
	ts, c := newConfigGatedServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/config",
		bytes.NewReader([]byte(`{"content":"[ui]\n"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://localhost:2967")
	req.Header.Set("X-Byn-Config-Auth", "goodtoken")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST /api/config: %v", err)
	}
	defer resp.Body.Close()
	// The config-auth gate must have PASSED — i.e. the response is not a
	// config_auth_required rejection. (A downstream 401 from the dispatcher's own
	// credential check is fine; that's a separate gate, not ours.)
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode == http.StatusUnauthorized && body["error"] == "config_auth_required" {
		t.Fatalf("config write WITH valid sudo token rejected as config_auth_required; gate should have passed")
	}
}

// TestConfigRead_OpenNoToken: GET /api/config is open — config holds settings,
// not secrets (only writes are sudo-gated).
func TestConfigRead_OpenNoToken(t *testing.T) {
	ts, c := newConfigGatedServer(t)
	resp := getURL(t, c, ts.URL+"/api/config")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("config read = 401; reads must be open")
	}
}
