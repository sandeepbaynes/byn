package daemon

import (
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestBootstrapTokens_MintAndConsume: mint returns a 64-char hex token that
// can be consumed exactly once within the TTL.
func TestBootstrapTokens_MintAndConsume(t *testing.T) {
	b := newBootstrapTokens()
	now := time.Now()

	tok, err := b.mint(now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("token length = %d, want 64", len(tok))
	}

	// First consume succeeds.
	if !b.consume(tok, now.Add(1*time.Second)) {
		t.Error("consume: want true for valid token within TTL")
	}
	// Second consume (replay) fails — single-use.
	if b.consume(tok, now.Add(2*time.Second)) {
		t.Error("consume: want false for replayed token")
	}
}

// TestBootstrapTokens_Expired: token consumed after its TTL → false.
func TestBootstrapTokens_Expired(t *testing.T) {
	b := newBootstrapTokens()
	now := time.Now()

	tok, err := b.mint(now)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Consume 31 seconds after mint — past the 30s TTL.
	if b.consume(tok, now.Add(31*time.Second)) {
		t.Error("consume: want false for expired token")
	}
}

// TestBootstrapTokens_EmptyToken: consume("") → false.
func TestBootstrapTokens_EmptyToken(t *testing.T) {
	b := newBootstrapTokens()
	if b.consume("", time.Now()) {
		t.Error("consume empty token: want false")
	}
}

// TestBootstrapTokens_UnknownToken: consume with a token that was never minted.
func TestBootstrapTokens_UnknownToken(t *testing.T) {
	b := newBootstrapTokens()
	if b.consume("nosuchtoken", time.Now()) {
		t.Error("consume unknown token: want false")
	}
}

// TestBootstrapTokens_PrunesExpired: expired tokens are pruned on the next mint.
func TestBootstrapTokens_PrunesExpired(t *testing.T) {
	b := newBootstrapTokens()
	past := time.Now().Add(-2 * time.Minute) // already expired

	_, _ = b.mint(past)

	b.mu.Lock()
	before := len(b.m)
	b.mu.Unlock()
	if before != 1 {
		t.Fatalf("before prune: map size = %d, want 1", before)
	}

	// Mint again — the expired token should be pruned.
	_, _ = b.mint(time.Now())

	b.mu.Lock()
	after := len(b.m)
	b.mu.Unlock()
	if after != 1 {
		t.Errorf("after prune: map size = %d, want 1 (only the new token)", after)
	}
}

// TestWebBootstrap_IPC: the web.bootstrap op mints a consumable 64-char token
// via the daemon IPC socket.
func TestWebBootstrap_IPC(t *testing.T) {
	d, c := startTestDaemon(t)

	var resp ipc.WebBootstrapResp
	if err := c.Call(ipc.OpWebBootstrap, ipc.WebBootstrapReq{}, &resp); err != nil {
		t.Fatalf("web.bootstrap: %v", err)
	}
	if len(resp.Token) != 64 {
		t.Errorf("bootstrap token length = %d, want 64", len(resp.Token))
	}

	// The minted token must be consumable from the daemon's in-memory store.
	if !d.bootstrapTokens.consume(resp.Token, time.Now()) {
		t.Error("IPC-minted bootstrap token not consumable from daemon's store")
	}
}

// TestWebBootstrap_SingleUse: the web.bootstrap token can only be consumed once.
func TestWebBootstrap_SingleUse(t *testing.T) {
	d, c := startTestDaemon(t)

	var resp ipc.WebBootstrapResp
	if err := c.Call(ipc.OpWebBootstrap, ipc.WebBootstrapReq{}, &resp); err != nil {
		t.Fatalf("web.bootstrap: %v", err)
	}

	// First consume.
	if !d.bootstrapTokens.consume(resp.Token, time.Now()) {
		t.Fatal("first consume must succeed")
	}
	// Second consume — must fail (single-use).
	if d.bootstrapTokens.consume(resp.Token, time.Now()) {
		t.Error("second consume of bootstrap token must return false")
	}
}
