package passkey

import (
	"bytes"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestBeginLogin_ListsCredential(t *testing.T) {
	rp, err := New("http://localhost:2967")
	if err != nil {
		t.Fatal(err)
	}
	u := &User{ID: []byte("vault-1"), Name: "default", Creds: []webauthn.Credential{{ID: []byte{1, 2, 3}}}}
	opts, sess, err := BeginLogin(rp, u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if len(opts.Response.Challenge) == 0 {
		t.Error("no challenge in assertion options")
	}
	if sess == nil || len(sess.Challenge) == 0 {
		t.Error("no session challenge to persist")
	}
	found := false
	for _, c := range opts.Response.AllowedCredentials {
		if bytes.Equal(c.CredentialID, []byte{1, 2, 3}) {
			found = true
		}
	}
	if !found {
		t.Errorf("enrolled credential not offered in allowCredentials: %+v", opts.Response.AllowedCredentials)
	}
}

func TestFinishRegistration_BadBody(t *testing.T) {
	rp, _ := New("http://localhost:2967")
	u := &User{ID: []byte("v"), Name: "default"}
	if _, err := FinishRegistration(rp, u, &webauthn.SessionData{}, []byte("not json")); err == nil {
		t.Fatal("expected a parse error on a garbage attestation body")
	}
}

func TestFinishLogin_BadBody(t *testing.T) {
	rp, _ := New("http://localhost:2967")
	u := &User{ID: []byte("v"), Name: "default"}
	if _, err := FinishLogin(rp, u, &webauthn.SessionData{}, []byte("not json")); err == nil {
		t.Fatal("expected a parse error on a garbage assertion body")
	}
}
