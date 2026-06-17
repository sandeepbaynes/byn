package daemon

import (
	"testing"
	"time"
)

func TestExecTokenStore_MintRedeemRoundTrip(t *testing.T) {
	s := newExecTokenStore()
	argv := []string{"/bin/echo", "hi"}
	env := []string{"PATH=/usr/bin", "API_KEY=secret"}
	tok, err := s.mint(argv, env, "profile-x")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(tok) != execTokenLen {
		t.Fatalf("token len = %d, want %d", len(tok), execTokenLen)
	}
	gotArgv, gotEnv, gotProfile, ok := s.redeem(tok)
	if !ok {
		t.Fatal("redeem failed for a fresh token")
	}
	if len(gotArgv) != 2 || gotArgv[0] != "/bin/echo" || gotArgv[1] != "hi" {
		t.Errorf("argv = %v, want [/bin/echo hi]", gotArgv)
	}
	if len(gotEnv) != 2 || gotEnv[1] != "API_KEY=secret" {
		t.Errorf("env = %v, want the stored env", gotEnv)
	}
	if gotProfile != "profile-x" {
		t.Errorf("profile = %q, want profile-x", gotProfile)
	}
}

func TestExecTokenStore_OneTime(t *testing.T) {
	s := newExecTokenStore()
	tok, _ := s.mint([]string{"/bin/x"}, nil, "")
	if _, _, _, ok := s.redeem(tok); !ok {
		t.Fatal("first redeem should succeed")
	}
	if _, _, _, ok := s.redeem(tok); ok {
		t.Error("second redeem must fail (tokens are one-time)")
	}
}

func TestExecTokenStore_Expiry(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newExecTokenStore()
	s.now = func() time.Time { return now }
	tok, _ := s.mint([]string{"/bin/x"}, []string{"API_KEY=secret"}, "")
	now = now.Add(execTokenTTL + time.Second) // advance past the TTL
	if _, _, _, ok := s.redeem(tok); ok {
		t.Error("an expired token must not redeem")
	}
}

func TestExecTokenStore_UnknownAndEmpty(t *testing.T) {
	s := newExecTokenStore()
	if _, _, _, ok := s.redeem([]byte("not-a-real-token")); ok {
		t.Error("unknown token must not redeem")
	}
	if _, _, _, ok := s.redeem(nil); ok {
		t.Error("nil token must not redeem")
	}
}

// TestExecTokenStore_SweepOnMint: minting purges expired tokens, so an
// unredeemed token (helper crashed) does not linger with its secret env.
func TestExecTokenStore_SweepOnMint(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newExecTokenStore()
	s.now = func() time.Time { return now }
	old, _ := s.mint([]string{"/bin/old"}, []string{"SECRET=x"}, "")
	now = now.Add(execTokenTTL + time.Second)
	if _, _ = s.mint([]string{"/bin/new"}, nil, ""); len(s.tokens) != 1 {
		t.Errorf("after sweep+mint, store has %d tokens, want 1 (expired swept)", len(s.tokens))
	}
	if _, _, _, ok := s.redeem(old); ok {
		t.Error("swept (expired) token must be gone")
	}
}
