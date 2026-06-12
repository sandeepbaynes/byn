package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeBootstrap implements BootstrapConsumer for tests.
type fakeBootstrap struct {
	mu sync.Mutex
	// tokens maps bootstrap token → persistent portal token. "" value means
	// ConsumeBootstrap returns "".
	tokens map[string]string
	// consumed records which tokens were consumed.
	consumed []string
}

func (f *fakeBootstrap) ConsumeBootstrap(t string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		return ""
	}
	v, ok := f.tokens[t]
	if !ok {
		return ""
	}
	f.consumed = append(f.consumed, t)
	delete(f.tokens, t) // single-use: remove after first consume
	return v
}

// singleUseConsumer is a simple single-use, TTL-aware BootstrapConsumer for
// testing TTL and replay semantics inside the ui package (without importing
// the daemon package's bootstrapTokens type).
type singleUseConsumer struct {
	mu        sync.Mutex
	token     string
	expires   time.Time
	portalTok string
	used      bool
}

func newSingleUseConsumer(tok, portalTok string, ttl time.Duration) *singleUseConsumer {
	return &singleUseConsumer{token: tok, portalTok: portalTok, expires: time.Now().Add(ttl)}
}

func (s *singleUseConsumer) ConsumeBootstrap(t string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || t != s.token || time.Now().After(s.expires) {
		return ""
	}
	s.used = true
	return s.portalTok
}

const (
	testBootstrapTok = "bb00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	testPortalTok    = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
)

// newBootstrapServer returns a portal server with a real token gate and the
// provided BootstrapConsumer wired in.
func newBootstrapServer(t *testing.T, fb BootstrapConsumer) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := New(&fakeDisp{}, Config{
		Port:      0,
		Token:     testPortalTok,
		Bootstrap: fb,
	})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	return ts, &http.Client{}
}

// TestBootstrap_Happy: valid, unexpired token → 200 with portal_token.
func TestBootstrap_Happy(t *testing.T) {
	fb := &fakeBootstrap{tokens: map[string]string{testBootstrapTok: testPortalTok}}
	ts, c := newBootstrapServer(t, fb)

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap happy = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["portal_token"] != testPortalTok {
		t.Errorf("portal_token = %q, want %q", body["portal_token"], testPortalTok)
	}
	// Token must have been consumed (fakeBootstrap deletes it on consume).
	fb.mu.Lock()
	_, stillExists := fb.tokens[testBootstrapTok]
	fb.mu.Unlock()
	if stillExists {
		t.Error("bootstrap token was not consumed")
	}
}

// TestBootstrap_InvalidToken: unknown token → 401.
func TestBootstrap_InvalidToken(t *testing.T) {
	fb := &fakeBootstrap{tokens: map[string]string{}}
	ts, c := newBootstrapServer(t, fb)

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": "nosuchtoken"})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid bootstrap = %d, want 401", resp.StatusCode)
	}
}

// TestBootstrap_NoToken: empty token → 401.
func TestBootstrap_NoToken(t *testing.T) {
	fb := &fakeBootstrap{tokens: map[string]string{testBootstrapTok: testPortalTok}}
	ts, c := newBootstrapServer(t, fb)

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": ""})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("empty bootstrap token = %d, want 401", resp.StatusCode)
	}
}

// TestBootstrap_Replayed: consuming the same token twice → second call gets 401.
func TestBootstrap_Replayed(t *testing.T) {
	suc := newSingleUseConsumer(testBootstrapTok, testPortalTok, 5*time.Second)
	ts, c := newBootstrapServer(t, suc)

	// First call succeeds.
	resp1 := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first bootstrap = %d, want 200", resp1.StatusCode)
	}

	// Second call with same token → 401 (single-use).
	resp2 := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay bootstrap = %d, want 401", resp2.StatusCode)
	}
}

// TestBootstrap_Expired: expired token → 401.
func TestBootstrap_Expired(t *testing.T) {
	// TTL of -1 second means already expired.
	suc := newSingleUseConsumer(testBootstrapTok, testPortalTok, -1*time.Second)
	ts, c := newBootstrapServer(t, suc)

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired bootstrap = %d, want 401", resp.StatusCode)
	}
}

// TestBootstrap_CSRF: cross-origin POST → 403 (sameOrigin gate).
func TestBootstrap_CSRF(t *testing.T) {
	fb := &fakeBootstrap{tokens: map[string]string{testBootstrapTok: testPortalTok}}
	ts, c := newBootstrapServer(t, fb)

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://evil.example",
		map[string]string{"token": testBootstrapTok})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CSRF bootstrap = %d, want 403", resp.StatusCode)
	}
	// Token must NOT have been consumed despite the sameOrigin rejection.
	fb.mu.Lock()
	_, stillExists := fb.tokens[testBootstrapTok]
	fb.mu.Unlock()
	if !stillExists {
		t.Error("bootstrap token was consumed despite CSRF rejection — token was not protected")
	}
}

// TestBootstrap_NoBootstrapConsumer: when Bootstrap is nil → 503.
func TestBootstrap_NoBootstrapConsumer(t *testing.T) {
	srv := New(&fakeDisp{}, Config{Port: 0, Token: testPortalTok, Bootstrap: nil})
	ts := httptest.NewServer(srv.mux)
	t.Cleanup(ts.Close)
	c := &http.Client{}

	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("nil bootstrap = %d, want 503", resp.StatusCode)
	}
}

// TestBootstrap_UngatedByOwnerToken: the endpoint must not require
// X-Byn-Portal-Token (the caller doesn't have it yet — that's the whole point).
func TestBootstrap_UngatedByOwnerToken(t *testing.T) {
	fb := &fakeBootstrap{tokens: map[string]string{testBootstrapTok: testPortalTok}}
	ts, c := newBootstrapServer(t, fb)

	// No X-Byn-Portal-Token header — must still succeed (postWithToken passes
	// "" as the token argument, which the helper omits from the request).
	resp := postWithToken(t, c, ts.URL+"/api/session/bootstrap", "", "http://localhost:2967",
		map[string]string{"token": testBootstrapTok})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap without owner-token = %d, want 200", resp.StatusCode)
	}
}
