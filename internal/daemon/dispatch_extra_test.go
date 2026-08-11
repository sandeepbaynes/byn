package daemon

import (
	"errors"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// Helper: set up unlocked vault for tests below.
// After a successful unlock the session token minted by the daemon is stored
// in c.Session so all subsequent c.Call invocations automatically carry it.
// This mirrors real CLI behaviour (NU-3): the client attaches its session
// token to every request so value-touching ops are authorized without
// re-supplying credentials.
func initUnlocked(t *testing.T, c *ipc.Client, pw []byte) {
	t.Helper()
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("VaultInit: %v", err)
	}
	var unlockResp ipc.VaultUnlockResp
	tok, err := c.CallAndCaptureSession(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &unlockResp, nil)
	if err != nil {
		t.Fatalf("VaultUnlock: %v", err)
	}
	// Store session so subsequent calls carry it.
	c.Session = tok
}

func TestVaultList_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	var resp ipc.VaultListResp
	if err := c.Call(ipc.OpVaultList, ipc.VaultListReq{}, &resp); err != nil {
		t.Fatalf("VaultList: %v", err)
	}
	if len(resp.Vaults) == 0 {
		t.Fatal("expected at least one vault")
	}
}

func TestVaultDelete_RefusesDefault(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "default"}, &ipc.VaultDeleteResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("err = %v", err)
	}
	if er.Code != ipc.CodeBadRequest {
		t.Fatalf("Code = %v, want bad_request", er.Code)
	}
}

func TestEnvRename_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "stg"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("EnvCreate: %v", err)
	}
	if err := c.Call(ipc.OpEnvRename,
		ipc.EnvRenameReq{Project: "default", OldName: "stg", NewName: "staging"},
		&ipc.EnvRenameResp{}); err != nil {
		t.Fatalf("EnvRename: %v", err)
	}
	// Renaming default env is protected.
	err := c.Call(ipc.OpEnvRename,
		ipc.EnvRenameReq{Project: "default", OldName: "default", NewName: "primary"},
		&ipc.EnvRenameResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) || er.Code != ipc.CodeEnvProtected {
		t.Fatalf("rename default: err = %v", err)
	}
}

func TestRename_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "old", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "old", NewName: "new"}, &ipc.RenameResp{}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	// Rename non-existent → not found.
	err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "nope", NewName: "x"}, &ipc.RenameResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) || er.Code != ipc.CodeNotFound {
		t.Fatalf("missing rename: err = %v", err)
	}
}

func TestAuditTail_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	// Generate an event.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "k", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 10}, &tail); err != nil {
		t.Fatalf("AuditTail: %v", err)
	}
	if len(tail.Events) == 0 {
		t.Fatal("expected events")
	}
}

func TestAuditVerify_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "k", Value: []byte("v")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	var v ipc.AuditVerifyResp
	if err := c.Call(ipc.OpAuditVerify, ipc.AuditVerifyReq{}, &v); err != nil {
		t.Fatalf("AuditVerify: %v", err)
	}
	if v.BadIndex != -1 {
		t.Fatalf("BadIndex = %d, want -1 (clean)", v.BadIndex)
	}
	if v.Total < 1 {
		t.Fatalf("Total = %d, want >= 1", v.Total)
	}
}

func TestDoctor_OverIPC(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("p")
	initUnlocked(t, c, pw)
	var r ipc.DoctorResp
	if err := c.Call(ipc.OpDoctor, ipc.DoctorReq{}, &r); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if len(r.Checks) == 0 {
		t.Fatal("no checks")
	}
}

func TestDoctor_WithoutVault(t *testing.T) {
	// No init — should still return some checks (probably warning).
	_, c := startTestDaemon(t)
	var r ipc.DoctorResp
	if err := c.Call(ipc.OpDoctor, ipc.DoctorReq{}, &r); err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	_ = r
}

func TestMapVaultErr_DefaultPath(t *testing.T) {
	// Generic non-vault error → internalErr.
	env := mapVaultErr("id1", errors.New("random"))
	if env.Err == nil || env.Err.Code != ipc.CodeInternal {
		t.Fatalf("err = %+v", env.Err)
	}
}

func TestBadRequestAndInternalErr(t *testing.T) {
	a := badRequest("id1", errors.New("x"))
	if a.Err.Code != ipc.CodeBadRequest {
		t.Fatalf("got %v", a.Err.Code)
	}
	b := internalErr("id1", errors.New("y"))
	if b.Err.Code != ipc.CodeInternal {
		t.Fatalf("got %v", b.Err.Code)
	}
}

func TestDefaultIfEmpty(t *testing.T) {
	if defaultIfEmpty("", "x") != "x" {
		t.Fatal("empty -> default")
	}
	if defaultIfEmpty("y", "x") != "y" {
		t.Fatal("nonempty passthrough")
	}
}

func TestOutcomeFor_OK(t *testing.T) {
	out, code := outcomeFor(&ipc.Envelope{})
	if out != "ok" || code != "" {
		t.Fatalf("got %q/%q", out, code)
	}
	// nil envelope path.
	out, code = outcomeFor(nil)
	if out != "ok" || code != "" {
		t.Fatalf("nil: got %q/%q", out, code)
	}
}

func TestOutcomeFor_NotFound(t *testing.T) {
	env := ipc.NewError("id", ipc.CodeNotFound, "no", "")
	out, code := outcomeFor(env)
	if out != "not_found" || code != string(ipc.CodeNotFound) {
		t.Fatalf("got %q/%q", out, code)
	}
}

func TestOutcomeFor_Denied(t *testing.T) {
	for _, c := range []ipc.ErrCode{ipc.CodeLocked, ipc.CodeWrongPassword, ipc.CodeRateLimited,
		ipc.CodeAlreadyExists, ipc.CodeAlreadyInit, ipc.CodeBadName, ipc.CodeBadRequest, ipc.CodeEnvProtected} {
		env := ipc.NewError("id", c, "x", "")
		out, _ := outcomeFor(env)
		if out != "denied" {
			t.Fatalf("%v -> %q", c, out)
		}
	}
}

func TestOutcomeFor_GenericError(t *testing.T) {
	env := ipc.NewError("id", ipc.CodeInternal, "boom", "")
	out, _ := outcomeFor(env)
	if out != "error" {
		t.Fatalf("got %q", out)
	}
}

func TestZero_Daemon(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	for _, x := range b {
		if x != 0 {
			t.Fatal("not zeroed")
		}
	}
}

func TestStoreForVault_BadName(t *testing.T) {
	d, c := startTestDaemon(t)
	_ = d
	err := c.Call(ipc.OpProjectList, ipc.ProjectListReq{Vault: "../bad"}, &ipc.ProjectListResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("err = %v", err)
	}
	if er.Code != ipc.CodeBadName {
		t.Fatalf("Code=%v", er.Code)
	}
}

func TestStoreForVault_NotInitialized(t *testing.T) {
	_, c := startTestDaemon(t)
	// Default vault not initialized → ListProjects returns CodeNotInit.
	err := c.Call(ipc.OpProjectList, ipc.ProjectListReq{}, &ipc.ProjectListResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("err = %v", err)
	}
	if er.Code != ipc.CodeNotInit {
		t.Fatalf("Code=%v", er.Code)
	}
}

// A daemon started deliberately as root with --allow-root must still answer
// root. Provisioning records the HUMAN owner, so without this the daemon
// allowlisted someone else and refused the very caller that started it — a
// daemon nobody can talk to, which is not a safer state, just a broken one.
func TestPeerGate_AllowRootDaemonAnswersRoot(t *testing.T) {
	cases := []struct {
		name      string
		uid       uint32
		ownerUID  uint32
		allowRoot bool
		want      bool // may connect
	}{
		{"root caller, allow-root daemon", 0, 1000, true, true},
		{"root caller, normal daemon", 0, 1000, false, false},
		{"owner always allowed", 1000, 1000, false, true},
		{"stranger refused even with allow-root", 1234, 1000, true, false},
	}
	// Both gates must agree. The connection gate admitting root while the
	// operation gate classified it as the exec helper is what left the daemon
	// answering nothing but token redemptions.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Mirrors the gate in dispatch: owner, exec helper, or an
			// explicitly-permitted root caller.
			allowedRoot := tc.uid == 0 && tc.allowRoot
			got := tc.uid == tc.ownerUID || allowedRoot
			if got != tc.want {
				t.Errorf("may connect = %v, want %v", got, tc.want)
			}
		})
	}
}

// A daemon started with --allow-root has a root OPERATOR, not just a root
// helper. isExecHelperUID treats root as the helper — correct when the helper
// is the only thing running as root — so without this the operation gate
// restricted the operator to redeeming exec tokens and refused everything else.
// Provisioning records the human owner (a sudo caller records SUDO_UID, not 0),
// so root matched neither owner nor permitted peer.
func TestOperationGate_AllowRootIsTreatedAsOwner(t *testing.T) {
	cases := []struct {
		name              string
		uid, ownerUID     uint32
		allowRoot, helper bool
		wantOwner         bool
	}{
		{"root operator under allow-root", 0, 1001, true, true, true},
		{"root helper on a normal daemon", 0, 1001, false, true, false},
		{"the recorded owner", 1001, 1001, false, false, true},
		{"a stranger", 1234, 1001, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowedRoot := tc.uid == 0 && tc.allowRoot
			isOwner := tc.uid == tc.ownerUID || allowedRoot
			if isOwner != tc.wantOwner {
				t.Fatalf("isOwner = %v, want %v", isOwner, tc.wantOwner)
			}
			// The restriction that broke privsep: helper peers that are not the
			// owner may only redeem exec tokens.
			restricted := tc.helper && !isOwner
			if tc.name == "root operator under allow-root" && restricted {
				t.Error("the operator was restricted to redeeming exec tokens")
			}
		})
	}
}
