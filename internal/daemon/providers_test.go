package daemon

// providers_test.go — EE-seam acceptance tests.
//
// These tests prove that a provider registered into the daemon's auth registry
// actually participates in authorization with NO changes to dispatch.go — this
// is the pluggability guarantee required by the project rules (EE injects its
// own providers without forking the base).
//
// EE registers providers here (see project rules: pluggability is mandatory);
// exported in NU-4.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// ---- stub providers --------------------------------------------------------

// namedApproveProvider always approves, registered under a given name.
// Used to override "password" in EE-seam tests.
type namedApproveProvider struct{ name string }

func (p *namedApproveProvider) Name() string { return p.name }
func (p *namedApproveProvider) Verify(_ context.Context, _ auth.VerifyRequest) (auth.Grant, error) {
	return auth.Grant{Provider: p.name}, nil
}

// namedDenyProvider always returns ErrWrongCredential, registered under a
// given name. Used to verify a registered provider's denial is respected.
type namedDenyProvider struct{ name string }

func (p *namedDenyProvider) Name() string { return p.name }
func (p *namedDenyProvider) Verify(_ context.Context, _ auth.VerifyRequest) (auth.Grant, error) {
	return auth.Grant{}, auth.ErrWrongCredential
}

// cancellingProvider honours ctx cancellation. Simulates a device-approval
// request that blocks until the owner responds (or the ctx times out).
type cancellingProvider struct{}

func (p *cancellingProvider) Name() string { return "fake-cancel" }
func (p *cancellingProvider) Verify(ctx context.Context, _ auth.VerifyRequest) (auth.Grant, error) {
	select {
	case <-ctx.Done():
		return auth.Grant{}, ctx.Err()
	case <-time.After(10 * time.Second): // never fires in test
		return auth.Grant{Provider: p.Name()}, nil
	}
}

// ---- Registry: built-in providers are reachable after New() ---------------

func TestDaemon_RegistryHasPasswordAndPasskeyAfterNew(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, name := range []string{"password", "passkey"} {
		if _, ok := d.authProviders.Lookup(name); !ok {
			t.Errorf("provider %q not registered after New()", name)
		}
	}
}

// ---- EE-seam: fake-approve overrides "password", gates pass ---------------

// TestEESeam_FakeApproveProvider: register a fake "password" provider that
// always approves. A per-action gated get supplied with an INCORRECT password
// should succeed — proving that the registered provider's decision (approve)
// is authoritative and overrides real credential verification. No dispatch.go
// edits needed.
//
// Note: the "no credential at all" short-circuit in authorizeAction returns
// CodeAuthRequired before reaching any provider (by design — a provider
// without a credential to inspect cannot make an informed decision). This test
// uses a wrong password to route into the provider, demonstrating that the
// provider's approve decision wins.
func TestEESeam_FakeApproveProvider(t *testing.T) {
	dir := shortTempDir(t)
	// The authorization gate is always active under the NU-3 session matrix.
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "SECRET", Value: []byte("s3cret")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Clear the session to force the password path (we want to test the provider,
	// not the session gate).
	c.Session = nil

	// Before injection: get with a wrong password → wrong_password.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "SECRET", Password: []byte("wrong")}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("pre-seam: code = %v, want wrong_password", code)
	}
	// Reset the rate limiter so the next attempt is not blocked.
	_ = d.limiter.RecordSuccess()

	// Register a fake "password" provider that always approves (EE override).
	d.authProviders.Register(&namedApproveProvider{name: "password"})

	// After injection: get with a wrong password succeeds — the registered
	// provider approves regardless of the credential value.
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "SECRET", Password: []byte("wrong")}, &resp); err != nil {
		t.Fatalf("post-seam get with fake-approve: %v", err)
	}
	if string(resp.Value) != "s3cret" {
		t.Errorf("value = %q, want s3cret", resp.Value)
	}

	// Restore the real password provider.
	d.authProviders.Register(&passwordProvider{d: d})
}

// ---- EE-seam: fake-deny blocks even a correct password --------------------

// TestEESeam_FakeDenyProvider: register a fake "password" provider that always
// returns ErrWrongCredential. Even supplying the correct password must result
// in denial — proving the registered provider's decision is authoritative.
func TestEESeam_FakeDenyProvider(t *testing.T) {
	dir := shortTempDir(t)
	// The authorization gate is always active under the NU-3 session matrix.
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}

	// Clear the session to force the password path (we want to test the provider).
	c.Session = nil

	// Register a deny provider under "password".
	d.authProviders.Register(&namedDenyProvider{name: "password"})

	// Even a correct password is denied.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "K", Password: pw}, &ipc.GetResp{})
	if err == nil {
		t.Fatal("expected denial, got nil error")
	}
	var ipcErr *ipc.ErrResponse
	if !errors.As(err, &ipcErr) {
		t.Fatalf("expected *ipc.ErrResponse, got %T: %v", err, err)
	}
	// The mapped code is wrong_password (ErrWrongCredential → CodeWrongPassword).
	if ipcErr.Code != ipc.CodeWrongPassword {
		t.Fatalf("code = %v, want wrong_password", ipcErr.Code)
	}

	// Restore.
	d.authProviders.Register(&passwordProvider{d: d})
}

// ---- EE-seam: ctx cancellation honoured ------------------------------------

// TestEESeam_CtxCancellationHonoured: a blocking provider that selects on
// ctx.Done returns ctx.Err when the context is cancelled — proving a device-
// approval provider can be timed out correctly.
func TestEESeam_CtxCancellationHonoured(t *testing.T) {
	reg := auth.NewRegistry()
	reg.Register(&cancellingProvider{})

	p, ok := reg.Lookup("fake-cancel")
	if !ok {
		t.Fatal("fake-cancel not found")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := p.Verify(ctx, auth.VerifyRequest{Vault: "default", Action: "get"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// ---- Passkey provider: token lifecycle via registry -----------------------

// TestPasskeyProvider_TokenConsumedByRegistry: mint a presence token, look up
// the passkey provider via the registry, call Verify — token is consumed and
// returns a Grant. Second use is denied.
func TestPasskeyProvider_TokenConsumedByRegistry(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tok, err := d.presenceTokens.mint("default", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	p, ok := d.authProviders.Lookup("passkey")
	if !ok {
		t.Fatal("passkey provider not in registry")
	}

	g, err := p.Verify(context.Background(), auth.VerifyRequest{
		Vault:         "default",
		PresenceToken: tok,
	})
	if err != nil {
		t.Fatalf("first Verify: unexpected error %v", err)
	}
	if g.Provider != "passkey" {
		t.Fatalf("Grant.Provider = %q, want passkey", g.Provider)
	}

	// Second use must be denied (token burned).
	_, err = p.Verify(context.Background(), auth.VerifyRequest{
		Vault:         "default",
		PresenceToken: tok,
	})
	if !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("token replay: err = %v, want auth.ErrDenied", err)
	}
}

// TestPasskeyProvider_WrongVaultDenied: token minted for one vault is denied
// when presented against a different vault, and burned so it can't be replayed.
func TestPasskeyProvider_WrongVaultDenied(t *testing.T) {
	dir := shortTempDir(t)
	d, err := New(Config{Dir: dir, Version: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tok, err := d.presenceTokens.mint("other", time.Now())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	p, ok := d.authProviders.Lookup("passkey")
	if !ok {
		t.Fatal("passkey provider not in registry")
	}

	// Wrong vault → denied.
	_, err = p.Verify(context.Background(), auth.VerifyRequest{
		Vault:         "default",
		PresenceToken: tok,
	})
	if !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("wrong vault: err = %v, want auth.ErrDenied", err)
	}

	// Correct vault → also denied (token burned by the failed attempt).
	_, err = p.Verify(context.Background(), auth.VerifyRequest{
		Vault:         "other",
		PresenceToken: tok,
	})
	if !errors.Is(err, auth.ErrDenied) {
		t.Fatalf("burned token on correct vault: err = %v, want auth.ErrDenied", err)
	}
}

// ---- EE-seam: fake-approve overrides "password" for trust.grant ----------

// TestEESeam_FakeApproveProvider_TrustGrant: register a fake "password"
// provider that always approves. A trust.grant with a WRONG password should
// succeed — proving that re-trust works through ANY provider registered under
// "password" with zero edits to dispatch.go or bynwrite.go.
//
// This is the canonical EE seam for the trust path: an EE can plug in a
// device-approval provider so that re-trusting an agent-edited .byn requires
// approval on the owner's phone, with no base code changes.
func TestEESeam_FakeApproveProvider_TrustGrant(t *testing.T) {
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)

	// Before injection: trust grant with a wrong password → wrong_password.
	err := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, Password: []byte("wrong")}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("pre-seam: code = %v, want wrong_password", code)
	}
	// Reset the rate limiter so the next attempt is not blocked.
	_ = d.limiter.RecordSuccess()

	// Register a fake "password" provider that always approves (EE override).
	d.authProviders.Register(&namedApproveProvider{name: "password"})

	// After injection: trust grant with a wrong password succeeds — the
	// registered provider approves regardless of the credential value.
	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, Password: []byte("wrong")}, &resp); err != nil {
		t.Fatalf("post-seam trust grant with fake-approve: %v", err)
	}
	if !bynTrusted(t, d, p, bynBody) {
		t.Fatal("after EE-seam trust grant the .byn is not trusted")
	}

	// Assert MAC integrity: look up the stored record and verify both MACs
	// with keys derived the same way the daemon derives them at grant time.
	rec, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if !ok {
		t.Fatal("record not found after EE-seam trust grant")
	}
	entry, oerr := d.openVault(context.Background(), "default")
	if oerr != nil {
		t.Fatalf("openVault: %v", oerr)
	}
	vkKey, derr := entry.store.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		t.Fatalf("DeriveSubkey: %v", derr)
	}
	if !rec.VerifyFPMAC(d.fpMACKey) {
		t.Error("VerifyFPMAC returned false after EE-seam trust grant")
	}
	if !rec.VerifyVKMAC(vkKey) {
		t.Error("VerifyVKMAC returned false after EE-seam trust grant")
	}

	// Restore the real password provider.
	d.authProviders.Register(&passwordProvider{d: d})
}

// TestEESeam_FakeApproveProvider_TrustGrant_LockedVault: EE provider APPROVED
// but vault is LOCKED and password is wrong (can't derive key). The safety-
// valve must return CodeLocked with an actionable hint — never CodeInternal —
// and no trust record must be written.
func TestEESeam_FakeApproveProvider_TrustGrant_LockedVault(t *testing.T) {
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	p := writeByn(t, bynBody)

	// Lock the vault so DeriveSubkeyWithPassword will fail (wrong password,
	// in-memory path unavailable).
	lockVaultStore(t, d, "default")

	// Register a fake "password" provider that always approves.
	d.authProviders.Register(&namedApproveProvider{name: "password"})

	// Trust grant with wrong password on locked vault → CodeLocked (not internal).
	grantErr := c.Call(ipc.OpTrustGrant,
		ipc.TrustGrantReq{Path: p, Password: []byte("wrong")}, &ipc.TrustGrantResp{})
	if code := errCode(t, grantErr); code != ipc.CodeLocked {
		t.Fatalf("EE-approve + locked vault: code = %v, want locked", code)
	}
	// No trust record must have been written.
	if bynTrusted(t, d, p, bynBody) {
		t.Fatal("trust was recorded on a locked vault via EE-seam approval")
	}
	var ipcErr *ipc.ErrResponse
	if errors.As(grantErr, &ipcErr) {
		if ipcErr.Recover == "" {
			t.Error("CodeLocked response should carry a non-empty Recover hint")
		}
	}

	// Restore the real password provider.
	d.authProviders.Register(&passwordProvider{d: d})
}

// ---- Password provider: correct/wrong/rate-limited via registry -----------

// TestPasswordProvider_VerifyThroughRegistry: password provider in the
// registry correctly approves a correct password and rejects a wrong one.
func TestPasswordProvider_VerifyThroughRegistry(t *testing.T) {
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p, ok := d.authProviders.Lookup("password")
	if !ok {
		t.Fatal("password provider not in registry")
	}

	// Correct password → Grant, nil.
	g, err := p.Verify(context.Background(), auth.VerifyRequest{
		Vault:    "default",
		Action:   "get",
		Password: pw,
	})
	if err != nil {
		t.Fatalf("correct pw: err = %v", err)
	}
	if g.Provider != "password" {
		t.Fatalf("Grant.Provider = %q, want password", g.Provider)
	}

	// Wrong password → ErrWrongCredential.
	_, err = p.Verify(context.Background(), auth.VerifyRequest{
		Vault:    "default",
		Action:   "get",
		Password: []byte("wrong-pw"),
	})
	if !errors.Is(err, auth.ErrWrongCredential) {
		t.Fatalf("wrong pw: err = %v, want auth.ErrWrongCredential", err)
	}
}

// TestPasswordProvider_RateLimitedAfterFailure: after forcing a failure into
// the limiter, the next Verify returns *auth.RetryAfterError directly.
func TestPasswordProvider_RateLimitedAfterFailure(t *testing.T) {
	dir := shortTempDir(t)
	d := startBareDaemon(t, Config{Dir: dir})
	c := ipc.NewClient(d.SocketPath())

	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p, ok := d.authProviders.Lookup("password")
	if !ok {
		t.Fatal("password provider not in registry")
	}

	// Force backoff directly through the limiter.
	_ = d.limiter.RecordFailure()

	_, err := p.Verify(context.Background(), auth.VerifyRequest{
		Vault:    "default",
		Action:   "get",
		Password: pw,
	})
	if err == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
	var rae *auth.RetryAfterError
	if !errors.As(err, &rae) {
		t.Fatalf("err = %v (%T), want *auth.RetryAfterError", err, err)
	}
}
