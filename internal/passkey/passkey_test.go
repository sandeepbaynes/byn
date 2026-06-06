package passkey

import "testing"

func TestNew_Valid(t *testing.T) {
	rp, err := New("http://localhost:2967")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if rp == nil {
		t.Fatal("nil relying party")
	}
}

// rp.id must be exactly "localhost" — locked by the PRF spike; changing it
// would orphan every enrolled passkey.
func TestBeginRegistration_Options(t *testing.T) {
	rp, err := New("http://localhost:2967")
	if err != nil {
		t.Fatal(err)
	}
	u := &User{ID: []byte("vault-uuid-1234"), Name: "default"}
	opts, sess, err := BeginRegistration(rp, u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if got := opts.Response.RelyingParty.ID; got != "localhost" {
		t.Errorf("rp.id = %q, want localhost", got)
	}
	if len(opts.Response.Challenge) == 0 {
		t.Error("no challenge in the creation options")
	}
	if sess == nil || len(sess.Challenge) == 0 {
		t.Error("no session challenge to persist server-side")
	}
}
