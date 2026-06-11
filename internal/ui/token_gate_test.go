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

// TestTokenGate_MissingToken: /api/* without token → 401 portal_token_required.
func TestTokenGate_MissingToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := getWithToken(t, c, ts.URL+"/api/status", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "portal_token_required" {
		t.Errorf("error = %q, want portal_token_required", body["error"])
	}
}

// TestTokenGate_WrongToken: /api/* with wrong token → 401 portal_token_required.
func TestTokenGate_WrongToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := getWithToken(t, c, ts.URL+"/api/status", "wrongtoken")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "portal_token_required" {
		t.Errorf("error = %q, want portal_token_required", body["error"])
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

// TestTokenGate_PostMissingToken: POST /api/unlock without token → 401.
func TestTokenGate_PostMissingToken(t *testing.T) {
	ts, c := newGatedTestServer(t)
	resp := postWithToken(t, c, ts.URL+"/api/unlock", "", "",
		map[string]string{"vault": "default", "password": "pw"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST without token = %d, want 401", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "portal_token_required" {
		t.Errorf("error = %q, want portal_token_required", body["error"])
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

// TestTokenGate_AndCSRF_MissingToken_IgnoresOrigin: a request with no token
// at all is rejected (401) even if origin would be accepted — the token gate
// fires first.
func TestTokenGate_AndCSRF_MissingToken_IgnoresOrigin(t *testing.T) {
	ts, c := newGatedTestServer(t)
	// No token, correct-looking origin → still 401 (token gate fires first).
	resp := postWithToken(t, c, ts.URL+"/api/entry/delete", "", "http://localhost:2967",
		map[string]any{"scope": map[string]string{"vault": "default"}, "name": "K"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token+correct-origin = %d, want 401", resp.StatusCode)
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

// TestTokenGate_DisabledWhenEmpty: when the server is constructed with an
// empty token, the gate is disabled and /api/* routes are reachable without
// any token header. This is the existing test behaviour.
func TestTokenGate_DisabledWhenEmpty(t *testing.T) {
	// newTestServer sets Token:"" (gate disabled).
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/status")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ungated status = %d, want 200", resp.StatusCode)
	}
}
