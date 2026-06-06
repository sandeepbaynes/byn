package ui

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestPasskeyRegisterBegin_ReturnsOptions(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/passkey/register/begin", "http://localhost:2967", map[string]any{"vault": "default"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got struct {
		CeremonyID string          `json:"ceremony_id"`
		Options    json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.CeremonyID == "" || len(got.Options) == 0 {
		t.Fatalf("missing ceremony_id/options: %+v", got)
	}
}

func TestPasskeyRegisterBegin_CrossOriginRefused(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/passkey/register/begin", "http://evil.example", map[string]any{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want 403", resp.StatusCode)
	}
}

func TestPasskeyAuthFinish_IssuesSession(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := post(t, c, ts.URL+"/api/passkey/auth/finish", "http://localhost:2967",
		map[string]any{"vault": "default", "ceremony_id": "cauth", "response": map[string]any{"id": "x"}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			cookie = ck
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("auth/finish did not set a session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}

	// The cookie now authenticates a session.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/passkey/session", nil)
	req.AddCookie(cookie)
	sresp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sresp.Body.Close()
	var sess struct {
		Authenticated bool   `json:"authenticated"`
		Vault         string `json:"vault"`
	}
	_ = json.NewDecoder(sresp.Body).Decode(&sess)
	if !sess.Authenticated || sess.Vault != "default" {
		t.Fatalf("session not authenticated: %+v", sess)
	}
}

func TestPasskeySession_NoCookie(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/passkey/session")
	defer resp.Body.Close()
	var sess struct {
		Authenticated bool `json:"authenticated"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sess)
	if sess.Authenticated {
		t.Fatal("no cookie should mean not authenticated")
	}
}

func TestPasskeyList_Forwards(t *testing.T) {
	ts, c := newTestServer(t, &fakeDisp{})
	resp := getURL(t, c, ts.URL+"/api/passkey/list?vault=default")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got struct {
		Passkeys []struct {
			Label string `json:"label"`
		} `json:"passkeys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Passkeys) != 1 || got.Passkeys[0].Label != "Touch ID" {
		t.Fatalf("unexpected list: %+v", got)
	}
}
