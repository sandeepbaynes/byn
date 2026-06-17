package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// provisionExecForTest marks the daemon as privsep-provisioned with a synthetic
// _byn-exec UID that is nonzero and distinct from the owner, so exec.authorize can
// mint tokens and exec.redeem accepts the helper.
func provisionExecForTest(d *Daemon) {
	d.execUID.Store(int64(d.ownerUID) + 1000) // nonzero and != ownerUID
	d.execProvisioned.Store(true)
}

// execUIDForTest returns the synthetic exec UID set by provisionExecForTest.
func execUIDForTest(d *Daemon) uint32 { return uint32(d.execUID.Load()) }

func authorizeEnvelope(t *testing.T, req ipc.ExecAuthorizeReq) *ipc.Envelope {
	t.Helper()
	env, err := ipc.NewRequest("auth-1", ipc.OpExecAuthorize, req)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return env
}

func redeemEnvelope(t *testing.T, req ipc.ExecRedeemReq) *ipc.Envelope {
	t.Helper()
	env, err := ipc.NewRequest("redeem-1", ipc.OpExecRedeem, req)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return env
}

// helperRedeemCtx returns a ctx whose caller UID is the _byn-exec service user —
// a valid redeemer.
func helperRedeemCtx(d *Daemon) context.Context {
	return withCaller(context.Background(), socketCaller(execUIDForTest(d), 1234, nil))
}

func envToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// TestExecAuthorize_TrustedPinned_MintsRedeemableToken: a trusted .byn with a
// pinned action authorizes free, mints a token, and the helper redeems it for the
// validated argv + curated env (injected secret present, dangerous key stripped)
// + the daemon's sandbox profile. The owner-UID CLI never sees the env.
func TestExecAuthorize_TrustedPinned_MintsRedeemableToken(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "API_KEY", []byte("secret-api"))
	provisionExecForTest(d)

	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	req := ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		BaseEnv:      []string{"PATH=/usr/bin", "LD_PRELOAD=/evil.so", "TMPDIR=/var/folders/owner-private/T"},
		AbsTarget:    target,
		Cwd:          "/proj",
	}
	resp := d.handleExecAuthorize(context.Background(), authorizeEnvelope(t, req))
	if resp.Err != nil {
		t.Fatalf("authorize error: %+v", resp.Err)
	}
	var ar ipc.ExecAuthorizeResp
	if err := ipc.DecodeBody(ipc.BodyResp, resp, &ar); err != nil {
		t.Fatalf("decode authorize resp: %v", err)
	}
	if len(ar.Token) == 0 {
		t.Fatal("authorize minted no token")
	}

	rresp := d.handleExecRedeem(helperRedeemCtx(d), redeemEnvelope(t, ipc.ExecRedeemReq{Token: ar.Token}))
	if rresp.Err != nil {
		t.Fatalf("redeem error: %+v", rresp.Err)
	}
	var rr ipc.ExecRedeemResp
	if err := ipc.DecodeBody(ipc.BodyResp, rresp, &rr); err != nil {
		t.Fatalf("decode redeem resp: %v", err)
	}
	if len(rr.Argv) != 2 || rr.Argv[0] != target || rr.Argv[1] != "run" {
		t.Errorf("argv = %v, want [%q run]", rr.Argv, target)
	}
	env := envToMap(rr.Env)
	if env["PATH"] != "/usr/bin" {
		t.Errorf("PATH = %q, want /usr/bin (from BaseEnv)", env["PATH"])
	}
	if env["API_KEY"] != "secret-api" {
		t.Errorf("API_KEY = %q, want secret-api (injected)", env["API_KEY"])
	}
	if _, bad := env["LD_PRELOAD"]; bad {
		t.Error("LD_PRELOAD survived into the curated child env")
	}
	if env["TMPDIR"] != childTmpDir {
		t.Errorf("TMPDIR = %q, want %q (owner's uid-private $TMPDIR must be normalized)", env["TMPDIR"], childTmpDir)
	}
	if rr.SandboxProfile != d.execSandboxProfile() {
		t.Errorf("redeemed profile does not match the daemon-generated profile")
	}
}

func TestNormalizeChildTmpdir(t *testing.T) {
	in := []string{"PATH=/usr/bin", "TMPDIR=/var/folders/x/T", "TMP=/var/folders/x/T", "TEMP=/var/folders/x/T", "HOME=/Users/me"}
	got := envToMap(normalizeChildTmpdir(in))
	if got["TMPDIR"] != childTmpDir || got["TMP"] != childTmpDir || got["TEMP"] != childTmpDir {
		t.Errorf("temp vars not normalized: TMPDIR=%q TMP=%q TEMP=%q", got["TMPDIR"], got["TMP"], got["TEMP"])
	}
	if got["PATH"] != "/usr/bin" || got["HOME"] != "/Users/me" {
		t.Error("non-temp vars must be preserved")
	}
	// Exactly one of each temp var (no duplicates from the strip+append).
	var n int
	for _, kv := range normalizeChildTmpdir(in) {
		if strings.HasPrefix(kv, "TMPDIR=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("TMPDIR appears %d times, want exactly 1", n)
	}
}

// TestExecRedeem_OneTime: a token redeems exactly once.
func TestExecRedeem_OneTime(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	provisionExecForTest(d)
	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	resp := d.handleExecAuthorize(context.Background(), authorizeEnvelope(t, ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}))
	if resp.Err != nil {
		t.Fatalf("authorize: %+v", resp.Err)
	}
	var ar ipc.ExecAuthorizeResp
	_ = ipc.DecodeBody(ipc.BodyResp, resp, &ar)

	if r := d.handleExecRedeem(helperRedeemCtx(d), redeemEnvelope(t, ipc.ExecRedeemReq{Token: ar.Token})); r.Err != nil {
		t.Fatalf("first redeem: %+v", r.Err)
	}
	if r := d.handleExecRedeem(helperRedeemCtx(d), redeemEnvelope(t, ipc.ExecRedeemReq{Token: ar.Token})); r.Err == nil {
		t.Error("second redeem must fail (one-time)")
	}
}

// TestExecRedeem_RejectsNonHelperUID: a caller that is neither root nor _byn-exec
// (e.g. the owner-UID CLI) is rejected, and the rejection happens BEFORE the token
// is consumed — so a real helper can still redeem it.
func TestExecRedeem_RejectsNonHelperUID(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	provisionExecForTest(d)
	target := regularFileTarget(t, "mytool")
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	resp := d.handleExecAuthorize(context.Background(), authorizeEnvelope(t, ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}))
	var ar ipc.ExecAuthorizeResp
	_ = ipc.DecodeBody(ipc.BodyResp, resp, &ar)

	// A uid that is guaranteed NOT a helper (not 0, not execUID).
	nonHelper := withCaller(context.Background(), socketCaller(execUIDForTest(d)+1, 222, nil))
	r := d.handleExecRedeem(nonHelper, redeemEnvelope(t, ipc.ExecRedeemReq{Token: ar.Token}))
	if r.Err == nil || r.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("non-helper redeem must be rejected, got %+v", r.Err)
	}
	// Token must survive a rejected attempt (gate runs before consumption).
	if r2 := d.handleExecRedeem(helperRedeemCtx(d), redeemEnvelope(t, ipc.ExecRedeemReq{Token: ar.Token})); r2.Err != nil {
		t.Errorf("helper redeem after a rejected non-helper attempt: %+v", r2.Err)
	}
}

// TestExecRedeem_UnknownToken: a bogus token is rejected for a valid helper.
func TestExecRedeem_UnknownToken(t *testing.T) {
	d, _ := startTestDaemon(t)
	provisionExecForTest(d)
	r := d.handleExecRedeem(helperRedeemCtx(d), redeemEnvelope(t, ipc.ExecRedeemReq{Token: []byte("bogus")}))
	if r.Err == nil || r.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("unknown token must be rejected, got %+v", r.Err)
	}
}

// TestExecAuthorize_NotProvisioned_FallbackError: with privsep unprovisioned,
// authorize returns a clean fallback error (the CLI runs the child in-process)
// rather than minting a token it cannot redeem.
func TestExecAuthorize_NotProvisioned_FallbackError(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	d.execProvisioned.Store(false) // force unprovisioned regardless of the test host
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	resp := d.handleExecAuthorize(context.Background(), authorizeEnvelope(t, ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    "/bin/true",
	}))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request when unprovisioned, got %+v", resp.Err)
	}
	if resp.Err.Recover != "byn setup" {
		t.Errorf("recover = %q, want 'byn setup'", resp.Err.Recover)
	}
}

// TestExecAuthorize_AbsTargetMismatch: a target whose basename does not match the
// authorized command is rejected (no token minted).
func TestExecAuthorize_AbsTargetMismatch(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	provisionExecForTest(d)
	target := regularFileTarget(t, "malware") // != authorized "mytool"
	byn := writeBynContent(t, "[scope]\n\n[exec]\nactions = [\"mytool run\"]\n")
	grantBynFile(t, c, byn, pw)

	resp := d.handleExecAuthorize(context.Background(), authorizeEnvelope(t, ipc.ExecAuthorizeReq{
		ExecFetchReq: ipc.ExecFetchReq{Path: byn, Command: "mytool run", Argv: []string{"mytool", "run"}},
		AbsTarget:    target,
	}))
	if resp.Err == nil || resp.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("want bad_request for basename mismatch, got %+v", resp.Err)
	}
}

// TestIsExecHelperUID: root always qualifies; the owner never does; the exec UID
// qualifies only when provisioned.
func TestIsExecHelperUID(t *testing.T) {
	d, _ := startTestDaemon(t)
	d.execProvisioned.Store(false)
	if !d.isExecHelperUID(0) {
		t.Error("root (0) must always be a helper uid")
	}
	if d.isExecHelperUID(99999) {
		t.Error("a non-root uid when unprovisioned must not qualify")
	}
	provisionExecForTest(d)
	if !d.isExecHelperUID(execUIDForTest(d)) {
		t.Error("the exec uid must qualify when provisioned")
	}
	if d.isExecHelperUID(execUIDForTest(d) + 1) {
		t.Error("an unrelated uid must never qualify")
	}
}
