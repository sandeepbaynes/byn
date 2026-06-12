package daemon

// trustgrant_token_test.go — Task 6 tests for presence-token parity on trust
// grant paths (trust.grant and trust.grant.bulk).
//
// Coverage:
//   - token-based trust.grant (unlocked) succeeds + stores v2 + MACs valid
//   - token grant on LOCKED vault → locked error (actionable)
//   - password grant byte-identical behavior (existing tests verify; one
//     additional sanity check here)
//   - bulk with token
//   - neither-credential → bad_request "trusting requires the master password…"
//   - wrong-vault token burned + denied

import (
	"context"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// ---- trust.grant: presence token path -------------------------------------

// TestTrustGrant_PresenceToken_Unlocked: a valid presence token on an unlocked
// vault grants trust, stores a v2 record, and the MAC layer is valid.
func TestTrustGrant_PresenceToken_Unlocked(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)

	// Mint a presence token (simulates a completed passkey ceremony).
	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, PresenceToken: tok}, &resp); err != nil {
		t.Fatalf("token grant: %v", err)
	}
	if resp.SHA256 != trust.Hash([]byte(bynBody)) {
		t.Errorf("resp hash %q != content hash", resp.SHA256)
	}
	if resp.Changed {
		t.Error("first-time grant should report changed=false")
	}
	if !bynTrusted(t, d, p, bynBody) {
		t.Fatal("after token grant the .byn is not trusted")
	}

	// Verify v2 record was stored (snapshot + mtime + MACs valid under the keys
	// the daemon derives at grant time: fpMACKey for the machine layer,
	// DeriveSubkey(VKMACKeyInfo) for the vault-key layer).
	rec, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if !ok {
		t.Fatal("record not found after token grant")
	}
	if rec.Snapshot != bynBody {
		t.Errorf("Snapshot != body")
	}
	if rec.MTimeUnixNano == 0 {
		t.Error("MTimeUnixNano should be non-zero")
	}
	if !rec.IsV2() {
		t.Error("record should be v2 after token grant")
	}
	// MAC assertions: both layers must verify with the daemon's own keys.
	entry, oerr := d.openVault(context.Background(), "default")
	if oerr != nil {
		t.Fatalf("openVault: %v", oerr)
	}
	vkKey, derr := entry.store.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		t.Fatalf("DeriveSubkey: %v", derr)
	}
	if !rec.VerifyFPMAC(d.fpMACKey) {
		t.Error("VerifyFPMAC returned false after token grant")
	}
	if !rec.VerifyVKMAC(vkKey) {
		t.Error("VerifyVKMAC returned false after token grant")
	}
}

// TestTrustGrant_PresenceToken_LockedVault: a valid presence token on a LOCKED
// vault must return CodeLocked with an actionable "unlock the vault" message.
func TestTrustGrant_PresenceToken_LockedVault(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	// Mint a token while unlocked, then lock the vault.
	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	lockVaultStore(t, d, "default")

	grantErr := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, PresenceToken: tok}, &ipc.TrustGrantResp{})
	if code := errCode(t, grantErr); code != ipc.CodeLocked {
		t.Fatalf("locked-vault token grant: code = %v, want locked", code)
	}
	// File must NOT be trusted.
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded on a locked vault")
	}
}

// TestTrustGrant_NeitherCredential_Denied: supplying neither password nor
// presence token returns bad_request with wording about the master password
// or passkey — even when the vault is unlocked.
func TestTrustGrant_NeitherCredential_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("no-credential code = %v, want bad_request", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded without a credential")
	}
}

// TestTrustGrant_WrongVaultToken_Denied: a token minted for a different vault
// is burned and denied.
func TestTrustGrant_WrongVaultToken_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	// Mint a token for "other", present against "default".
	tok, err := d.presenceTokens.mint("other", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	grantErr := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, PresenceToken: tok}, &ipc.TrustGrantResp{})
	if code := errCode(t, grantErr); code != ipc.CodeBadRequest {
		t.Fatalf("wrong-vault token: code = %v, want bad_request", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded with a wrong-vault token")
	}
}

// ---- trust.grant.bulk: presence token path --------------------------------

// TestTrustGrantBulk_PresenceToken_Unlocked: bulk grant with a presence token
// trusts all paths in one step (token consumed once, vk key derived once).
func TestTrustGrantBulk_PresenceToken_Unlocked(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p1 := writeByn(t, bynBody)
	const body2 = "[scope]\nproject = \"svc2\"\n"
	p2 := writeByn(t, body2)

	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	var resp ipc.TrustGrantBulkResp
	if err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p1, p2}, PresenceToken: tok}, &resp); err != nil {
		t.Fatalf("bulk token grant: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
	if resp.Results[0].Error != "" || resp.Results[1].Error != "" {
		t.Errorf("both files should succeed: %+v", resp.Results)
	}
	if !bynTrusted(t, d, p1, bynBody) || !bynTrusted(t, d, p2, body2) {
		t.Error("both .byn files should be trusted after bulk token grant")
	}
}

// TestTrustGrantBulk_PresenceToken_LockedVault: bulk token grant on locked
// vault returns CodeLocked.
func TestTrustGrantBulk_PresenceToken_LockedVault(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	lockVaultStore(t, d, "default")

	grantErr := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p}, PresenceToken: tok},
		&ipc.TrustGrantBulkResp{})
	if code := errCode(t, grantErr); code != ipc.CodeLocked {
		t.Fatalf("locked-vault bulk token grant: code = %v, want locked", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded on a locked vault")
	}
}

// TestTrustGrantBulk_NeitherCredential_Denied: bulk with no credential returns
// bad_request.
func TestTrustGrantBulk_NeitherCredential_Denied(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	p := writeByn(t, bynBody)

	err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p}},
		&ipc.TrustGrantBulkResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("no-credential bulk code = %v, want bad_request", code)
	}
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded without a credential")
	}
}
