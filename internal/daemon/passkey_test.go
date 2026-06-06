package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

func TestPasskeyRegisterBegin_Unlocked_ReturnsOptions(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	var resp ipc.PasskeyRegisterBeginResp
	if err := c.Call(ipc.OpPasskeyRegisterBegin, ipc.PasskeyRegisterBeginReq{}, &resp); err != nil {
		t.Fatalf("register-begin: %v", err)
	}
	if resp.CeremonyID == "" {
		t.Error("no ceremony id returned")
	}
	var opts map[string]any
	if err := json.Unmarshal(resp.Options, &opts); err != nil {
		t.Fatalf("options not valid JSON: %v", err)
	}
	pk, ok := opts["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("creation options missing publicKey: %v", opts)
	}
	if s, _ := pk["challenge"].(string); s == "" {
		t.Error("no challenge in creation options")
	}
	rp, _ := pk["rp"].(map[string]any)
	if rp == nil || rp["id"] != "localhost" {
		t.Errorf("rp.id != localhost: %v", rp)
	}
	// The account name macOS shows must be byn-scoped per vault.
	user, _ := pk["user"].(map[string]any)
	if user == nil || user["name"] != "byn-default" {
		t.Errorf("user.name = %v, want byn-default", user["name"])
	}
}

func TestPasskeyRegisterBegin_LockedRefused(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatal(err)
	}
	err := c.Call(ipc.OpPasskeyRegisterBegin, ipc.PasskeyRegisterBeginReq{}, &ipc.PasskeyRegisterBeginResp{})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("locked register-begin code = %v, want locked (enrollment needs unlock)", code)
	}
}

func TestPasskeyRegisterFinish_UnknownCeremony(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	err := c.Call(ipc.OpPasskeyRegisterFinish,
		ipc.PasskeyRegisterFinishReq{CeremonyID: "deadbeef", Response: json.RawMessage(`{}`)},
		&ipc.PasskeyRegisterFinishResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("unknown-ceremony code = %v, want bad_request", code)
	}
}

func TestPasskeyAuthBegin_NoCredentials(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	err := c.Call(ipc.OpPasskeyAuthBegin, ipc.PasskeyAuthBeginReq{}, &ipc.PasskeyAuthBeginResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("no-credentials auth-begin code = %v, want bad_request", code)
	}
}

func TestPasskeyList_Empty(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	var resp ipc.PasskeyListResp
	if err := c.Call(ipc.OpPasskeyList, ipc.PasskeyListReq{}, &resp); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Passkeys) != 0 {
		t.Fatalf("want 0 passkeys on a fresh vault, got %d", len(resp.Passkeys))
	}
}

func TestPasskeyRemove_RequiresPassword(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	err := c.Call(ipc.OpPasskeyRemove, ipc.PasskeyRemoveReq{CredentialID: []byte{1}}, &ipc.PasskeyRemoveResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("no-password remove code = %v, want bad_request", code)
	}
	err = c.Call(ipc.OpPasskeyRemove,
		ipc.PasskeyRemoveReq{CredentialID: []byte{1}, Password: []byte("nope")}, &ipc.PasskeyRemoveResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("wrong-password remove code = %v, want wrong_password", code)
	}
}

func TestPasskeyChallenges_PutTakeOnce(t *testing.T) {
	c := newPasskeyChallenges()
	now := time.Unix(1000, 0)
	id, err := c.put("default", &webauthn.SessionData{Challenge: "abc"}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	ch, ok := c.take(id, now)
	if !ok || ch.vault != "default" || ch.session.Challenge != "abc" {
		t.Fatalf("take failed: ok=%v ch=%+v", ok, ch)
	}
	if _, ok := c.take(id, now); ok {
		t.Error("a challenge must be consumed (one-time) after the first take")
	}
}

func TestPasskeyChallenges_Expired(t *testing.T) {
	c := newPasskeyChallenges()
	id, _ := c.put("default", &webauthn.SessionData{}, nil, time.Unix(1000, 0))
	if _, ok := c.take(id, time.Unix(1000, 0).Add(passkeyChallengeTTL+time.Second)); ok {
		t.Error("an expired challenge must not be returned")
	}
}

// register-begin must enable PRF + (Apple) request eval-at-create, so finish
// can wrap the vault key.
func TestPasskeyRegisterBegin_InjectsPRF(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	var resp ipc.PasskeyRegisterBeginResp
	if err := c.Call(ipc.OpPasskeyRegisterBegin, ipc.PasskeyRegisterBeginReq{}, &resp); err != nil {
		t.Fatal(err)
	}
	var opts map[string]any
	if err := json.Unmarshal(resp.Options, &opts); err != nil {
		t.Fatal(err)
	}
	pk, _ := opts["publicKey"].(map[string]any)
	ext, _ := pk["extensions"].(map[string]any)
	prf, _ := ext["prf"].(map[string]any)
	eval, _ := prf["eval"].(map[string]any)
	if s, _ := eval["first"].(string); s == "" {
		t.Fatalf("register-begin must inject prf.eval.first; got extensions=%v", ext)
	}
}

// Revoking a credential must also drop its PRF-unlock path (FK cascade), so a
// revoked passkey can never unlock the vault — no lock bypass via a stale key.
func TestPasskeyRemove_CascadesUnlock(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	st, errEnv := d.storeForVault("t", "default")
	if errEnv != nil {
		t.Fatalf("store: %v", errEnv)
	}
	ctx := context.Background()
	credID := []byte{5, 5, 5}
	if err := st.AddPasskey(ctx, vault.Passkey{CredentialID: credID, PublicKey: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPasskeyUnlock(ctx, vault.PasskeyUnlock{
		CredentialID: credID, PRFSalt: bytes.Repeat([]byte{1}, 32), WrappedVaultKey: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	var rm ipc.PasskeyRemoveResp
	if err := c.Call(ipc.OpPasskeyRemove,
		ipc.PasskeyRemoveReq{CredentialID: credID, Password: []byte(authzPW)}, &rm); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !rm.Removed {
		t.Fatal("expected removed=true")
	}
	if recs, _ := st.PasskeyUnlocks(ctx); len(recs) != 0 {
		t.Fatalf("revoke must cascade-delete the unlock record; got %d", len(recs))
	}
	var list ipc.PasskeyListResp
	_ = c.Call(ipc.OpPasskeyList, ipc.PasskeyListReq{}, &list)
	if len(list.Passkeys) != 0 {
		t.Fatalf("revoked passkey still listed: %d", len(list.Passkeys))
	}
}

// A ceremony id is single-use: replaying it after the first finish (challenge
// already consumed) is rejected, defeating response replay.
func TestPasskeyRegisterFinish_CeremonyIsOneTime(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	var begin ipc.PasskeyRegisterBeginResp
	if err := c.Call(ipc.OpPasskeyRegisterBegin, ipc.PasskeyRegisterBeginReq{}, &begin); err != nil {
		t.Fatal(err)
	}
	// First finish consumes the ceremony (it fails the bogus attestation, but
	// the one-time challenge is taken).
	_ = c.Call(ipc.OpPasskeyRegisterFinish,
		ipc.PasskeyRegisterFinishReq{CeremonyID: begin.CeremonyID, Response: json.RawMessage(`{}`)},
		&ipc.PasskeyRegisterFinishResp{})
	// Replaying the same ceremony id must be rejected.
	err := c.Call(ipc.OpPasskeyRegisterFinish,
		ipc.PasskeyRegisterFinishReq{CeremonyID: begin.CeremonyID, Response: json.RawMessage(`{}`)},
		&ipc.PasskeyRegisterFinishResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("replayed ceremony code = %v, want bad_request (one-time use)", code)
	}
}

// list reports per-credential unlock capability so the UI knows when to offer
// Touch ID unlock vs fall back to the password.
func TestPasskeyList_ReportsUnlockCapability(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	st, errEnv := d.storeForVault("t", "default")
	if errEnv != nil {
		t.Fatalf("store: %v", errEnv)
	}
	ctx := context.Background()
	if err := st.AddPasskey(ctx, vault.Passkey{CredentialID: []byte{1}, PublicKey: []byte("k"), Label: "session"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPasskey(ctx, vault.Passkey{CredentialID: []byte{2}, PublicKey: []byte("k"), Label: "unlock"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPasskeyUnlock(ctx, vault.PasskeyUnlock{
		CredentialID: []byte{2}, PRFSalt: bytes.Repeat([]byte{9}, 32), WrappedVaultKey: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.PasskeyListResp
	if err := c.Call(ipc.OpPasskeyList, ipc.PasskeyListReq{}, &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range resp.Passkeys {
		got[p.Label] = p.Unlock
	}
	if !got["unlock"] || got["session"] {
		t.Fatalf("unlock flags wrong: %+v", got)
	}
}

// auth-begin must request prf.evalByCredential for every credential that has a
// PRF-unlock record, so a good assertion also yields the unlock KEK.
func TestPasskeyAuthBegin_InjectsPRFForUnlockCreds(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))
	st, errEnv := d.storeForVault("t", "default")
	if errEnv != nil {
		t.Fatalf("store: %v", errEnv)
	}
	ctx := context.Background()
	credID := []byte{1, 2, 3}
	if err := st.AddPasskey(ctx, vault.Passkey{CredentialID: credID, PublicKey: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPasskeyUnlock(ctx, vault.PasskeyUnlock{
		CredentialID: credID, PRFSalt: bytes.Repeat([]byte{9}, 32), WrappedVaultKey: []byte("w"),
	}); err != nil {
		t.Fatal(err)
	}
	var resp ipc.PasskeyAuthBeginResp
	if err := c.Call(ipc.OpPasskeyAuthBegin, ipc.PasskeyAuthBeginReq{}, &resp); err != nil {
		t.Fatalf("auth-begin: %v", err)
	}
	var opts map[string]any
	if err := json.Unmarshal(resp.Options, &opts); err != nil {
		t.Fatal(err)
	}
	pk, _ := opts["publicKey"].(map[string]any)
	ext, _ := pk["extensions"].(map[string]any)
	prf, _ := ext["prf"].(map[string]any)
	eval, _ := prf["eval"].(map[string]any)
	if s, _ := eval["first"].(string); s == "" {
		t.Fatalf("auth-begin must inject prf.eval.first for a single unlock cred; got %v", ext)
	}
}
