package daemon

// policy_test.go — tests for policyFor and the per-action gate's [auth] policy
// integration. This file tests:
//
//   1. policy get="none" + flag ON  → get is free in that scope.
//   2. Same vault, different project → still gated (scope precision).
//   3. policy delete="always" + flag OFF → delete gated (unconditional path).
//   4. Locked vault → policy ignored (flag decides).
//   5. Record with invalid vk-MAC (hand-forged Auth edit) → ignored.
//   6. v1 record (no mtime/snapshot) → ignored.
//   7. Specificity: broad "none" + specific "always" → "always" for that scope.
//   8. Same-specificity tie → strictest ("always" beats "none").
//   9. rename maps to "update".
//  10. env.clear maps to "delete".
//  11. Absent trusted_byn.json (fresh install) → ok=false, flag decides.

import (
	"encoding/hex"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// ---- helpers ---------------------------------------------------------------

// grantBynPolicy grants a .byn with the given body AND vault+password and
// returns the trust record as stored (for MAC inspection).
func grantBynPolicy(t *testing.T, d *Daemon, c *ipc.Client, body string, vaultName string, pw []byte) {
	t.Helper()
	p := writeByn(t, body)
	req := ipc.TrustGrantReq{Path: p, Vault: vaultName, Password: pw}
	if err := c.Call(ipc.OpTrustGrant, req, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grantBynPolicy: %v", err)
	}
}

// forgeAuthInStore loads the trust store, finds the record matching path
// (by path prefix scan), replaces its Auth with forged values WITHOUT updating
// the MACs, and saves — simulating a tampered record.
func forgeAuthInStore(t *testing.T, dir string, path string, forgedAuth map[string]string) {
	t.Helper()
	s, err := trust.Load(dir)
	if err != nil {
		t.Fatalf("forgeAuthInStore Load: %v", err)
	}
	found := false
	for i := range s.Records {
		if s.Records[i].Path == trust.Canonicalize(path) {
			s.Records[i].Auth = forgedAuth
			// Intentionally NOT updating the MACs → tampered.
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("forgeAuthInStore: path %s not found in store", path)
	}
	if err := trust.Save(dir, s); err != nil {
		t.Fatalf("forgeAuthInStore Save: %v", err)
	}
}

// injectV1Record writes a v1 trust record (no mtime, no snapshot, no Auth)
// directly into the store, bypassing the daemon.
func injectV1Record(t *testing.T, dir, path string, auth map[string]string) {
	t.Helper()
	s, err := trust.Load(dir)
	if err != nil {
		t.Fatalf("injectV1Record Load: %v", err)
	}
	body := []byte("[scope]\nproject = \"v1proj\"\n")
	rec := trust.Record{
		Path:   trust.Canonicalize(path),
		SHA256: trust.Hash(body),
		Vault:  vault.DefaultVaultName,
		Auth:   auth,
		// MTimeUnixNano == 0 and Snapshot == "" → IsV2() returns false (v1).
	}
	s.Records = append(s.Records, rec)
	if err := trust.Save(dir, s); err != nil {
		t.Fatalf("injectV1Record Save: %v", err)
	}
}

// ---- test 11: absent trusted_byn.json -------------------------------------

// TestPolicyFor_NoStoreFile verifies that policyFor returns ok=false when
// trusted_byn.json does not exist (fresh install), causing flag semantics.
func TestPolicyFor_NoStoreFile(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// No trust file was written — fresh install.
	if _, ok := d.policyFor(vault.DefaultVaultName, vault.Scope{}); ok {
		t.Error("policyFor should return ok=false when trusted_byn.json is absent")
	}
}

// ---- test 1: policy get="none" + flag ON → free ----------------------------

// TestPolicyGet_None_FlagOn_FreeGet verifies that a trusted .byn with
// [auth] get="none" makes get free even when per_action_auth is ON.
func TestPolicyGet_None_FlagOn_FreeGet(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Trust a .byn with get="none" targeting the default scope.
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nget = \"none\"\n", vault.DefaultVaultName, pw)

	// Get without password — should succeed because policy says "none".
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "SECRET"}, &resp); err != nil {
		t.Fatalf("get with policy none: %v (expected free)", err)
	}
	if string(resp.Value) != "s3cret" {
		t.Errorf("value = %q, want s3cret", resp.Value)
	}
}

// ---- test 2: scope precision — same vault, different project still gated ---

// TestPolicyGet_None_DifferentProject_StillGated verifies that a policy record
// scoped to project="svc" does not relax the gate for project="other".
func TestPolicyGet_None_DifferentProject_StillGated(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create project "svc" and "other".
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create svc: %v", err)
	}
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "other"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create other: %v", err)
	}

	// Store a secret in project "other".
	otherScope := ipc.Scope{Project: "other"}
	putVar(t, c, otherScope, "KEY", []byte("val"))

	// Trust a .byn scoped to project="svc" with get="none".
	grantBynPolicy(t, d, c,
		"[scope]\nproject = \"svc\"\n\n[auth]\nget = \"none\"\n",
		vault.DefaultVaultName, pw)

	// Get from project "other" without password → still auth_required (wrong scope).
	err := c.Call(ipc.OpGet, ipc.GetReq{Scope: otherScope, Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("different-project get: code = %v, want auth_required (policy scope mismatch)", code)
	}
}

// ---- test 3: policy delete="always" + flag OFF → gated --------------------

// TestPolicyDelete_Always_FlagOff_Gated verifies that delete is gated when
// [auth] delete="always" even with per_action_auth OFF.
func TestPolicyDelete_Always_FlagOff_Gated(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v"))

	// Trust a .byn with delete="always".
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Delete without creds → auth_required (policy always, even though flag is off).
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY"}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("delete flag-off policy-always: code = %v, want auth_required", code)
	}

	// Delete with correct password → succeeds (no wrong-password attempt first to
	// avoid triggering rate-limiting for this test case).
	if err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY", Password: pw}, &ipc.DeleteResp{}); err != nil {
		t.Fatalf("delete with correct pw (policy always, flag off): %v", err)
	}
}

// TestPolicyDelete_Always_WrongPassword_Rejected verifies that a wrong password
// is rejected under policy="always" (not silently bypassed).
func TestPolicyDelete_Always_WrongPassword_Rejected(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v"))

	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Delete with wrong password → wrong_password (not free).
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY", Password: []byte("wrong")}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("wrong pw on policy always: code = %v, want wrong_password", code)
	}
}

// ---- test 4: locked vault → policy ignored (flag decides) -----------------

// TestPolicyFor_LockedVault_PolicyIgnored verifies that when the vault is
// locked, policyFor returns ok=false and flag semantics apply.
func TestPolicyFor_LockedVault_PolicyIgnored(t *testing.T) {
	d, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v"))

	// Trust a .byn with delete="always" (would gate if policy were respected).
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Lock the vault.
	lockVaultStore(t, d, vault.DefaultVaultName)

	// policyFor should return ok=false for a locked vault.
	if _, ok := d.policyFor(vault.DefaultVaultName, vault.Scope{}); ok {
		t.Error("policyFor should return ok=false when vault is locked")
	}

	// With flag OFF and vault locked, delete requires password via
	// authorizeMutationWhileLocked (flag path) — not via policy "always".
	// Without password → CodeLocked (not auth_required, which is the policy path).
	err := c.Call(ipc.OpDelete, ipc.DeleteReq{Name: "KEY"}, &ipc.DeleteResp{})
	if code := errCode(t, err); code != ipc.CodeLocked {
		t.Fatalf("locked+flag off: code = %v, want locked (policy ignored, not always-path)", code)
	}
}

// ---- test 5: tampered vk-MAC → record ignored ------------------------------

// TestPolicyFor_TamperedVKMAC_Ignored verifies that a record whose Auth was
// edited AFTER grant (breaking the VKMAC) is silently ignored.
func TestPolicyFor_TamperedVKMAC_Ignored(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("val"))

	// Trust a .byn with get="none".
	p := writeByn(t, "[scope]\n\n[auth]\nget = \"none\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Forge the Auth to something stricter WITHOUT updating the VKMAC.
	// policyFor must ignore this record.
	forgeAuthInStore(t, d.cfg.Dir, p, map[string]string{"get": "none", "delete": "none"})

	// Get without password — must be auth_required because the tampered
	// record is ignored and flag is ON.
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("tampered MAC: code = %v, want auth_required (record ignored)", code)
	}
}

// ---- test 6: v1 record → ignored ------------------------------------------

// TestPolicyFor_V1Record_Ignored verifies that a v1 record (IsV2=false) is
// not used as a policy source even if it has an Auth field.
func TestPolicyFor_V1Record_Ignored(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("val"))

	// Inject a v1 record (no mtime/snapshot) with get="none" directly.
	p := writeByn(t, "[scope]\n\n")
	injectV1Record(t, d.cfg.Dir, p, map[string]string{"get": "none"})

	// Get without password — must be auth_required (v1 record ignored).
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("v1 record: code = %v, want auth_required (v1 record ignored)", code)
	}
}

// ---- test 7: specificity — broad "none" + specific "always" → always ------

// TestPolicyFor_Specificity_SpecificAlwaysBeatsVaultNone verifies that a
// vault-only record with get="none" is overridden by a project-scoped record
// with get="always" when the request matches the specific scope.
func TestPolicyFor_Specificity_SpecificAlwaysBeatsVaultNone(t *testing.T) {
	d, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "restricted"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	putVar(t, c, ipc.Scope{Project: "restricted"}, "KEY", []byte("val"))

	// Vault-wide record: get="none" (broad; would free up gets).
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nget = \"none\"\n", vault.DefaultVaultName, pw)

	// Project-scoped record: get="always" (specific; must win for "restricted").
	grantBynPolicy(t, d, c,
		"[scope]\nproject = \"restricted\"\n\n[auth]\nget = \"always\"\n",
		vault.DefaultVaultName, pw)

	// Get from "restricted" project without creds → auth_required (specific "always" wins).
	err := c.Call(ipc.OpGet, ipc.GetReq{Scope: ipc.Scope{Project: "restricted"}, Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("specific always vs broad none: code = %v, want auth_required", code)
	}

	// But get from the default project (no project-scoped override) → free (broad "none").
	putVar(t, c, ipc.Scope{}, "KEY2", []byte("val2"))
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY2"}, &resp); err != nil {
		t.Fatalf("broad none default project: %v (expected free)", err)
	}
}

// ---- test 8: same-specificity tie → strictest value wins -------------------

// TestPolicyFor_SameSpecificity_StrictestWins verifies that when two records
// match at the same specificity level, the strictest value wins per key
// ("always" beats "none").
func TestPolicyFor_SameSpecificity_StrictestWins(t *testing.T) {
	d, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("val"))

	// Two vault-only records (same specificity): one says get="none", the other get="always".
	// Result must be get="always" (strictest wins).
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nget = \"none\"\n", vault.DefaultVaultName, pw)
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nget = \"always\"\n", vault.DefaultVaultName, pw)

	// policyFor should return "always" (strictest).
	policy, ok := d.policyFor(vault.DefaultVaultName, vault.Scope{
		Project: vault.DefaultProjectName,
		Env:     vault.DefaultEnvName,
	})
	if !ok {
		t.Fatal("policyFor returned ok=false, want a policy")
	}
	if policy["get"] != "always" {
		t.Errorf("policy[get] = %q, want always (strictest-tie wins)", policy["get"])
	}

	// Confirm via the gate: get without creds → auth_required (policy always).
	err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("tie-strictest: code = %v, want auth_required", code)
	}
}

// ---- test 9: rename maps to "update" --------------------------------------

// TestPolicyRename_Update_None_FlagOn_Free verifies that [auth] update="none"
// makes rename free even when per_action_auth is ON (rename maps to "update").
func TestPolicyRename_Update_None_FlagOn_Free(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "OLD", []byte("v"))

	// Trust a .byn with update="none".
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nupdate = \"none\"\n", vault.DefaultVaultName, pw)

	// Rename without creds — should succeed (policy none for update).
	if err := c.Call(ipc.OpRename, ipc.RenameReq{OldName: "OLD", NewName: "NEW"}, &ipc.RenameResp{}); err != nil {
		t.Fatalf("rename with update=none: %v (expected free)", err)
	}
}

// ---- test 10: env.clear maps to "delete" ----------------------------------

// TestPolicyEnvClear_Delete_None_FlagOn_Free verifies that [auth] delete="none"
// makes env.clear free even when per_action_auth is ON (env.clear maps to "delete").
func TestPolicyEnvClear_Delete_None_FlagOn_Free(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "K1", []byte("a"))
	putVar(t, c, ipc.Scope{}, "K2", []byte("b"))

	// Trust a .byn with delete="none".
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\ndelete = \"none\"\n", vault.DefaultVaultName, pw)

	// env.clear without creds — should succeed (policy none for delete).
	var clearResp ipc.EnvClearResp
	if err := c.Call(ipc.OpEnvClear, ipc.EnvClearReq{}, &clearResp); err != nil {
		t.Fatalf("env.clear with delete=none: %v (expected free)", err)
	}
	if clearResp.Deleted != 2 {
		t.Errorf("deleted = %d, want 2", clearResp.Deleted)
	}
}

// ---- policyFor unit test: unlocked returns correct policy values -----------

// TestPolicyFor_ReturnsAuthMap verifies the raw policyFor output for a simple
// v2 record with a known Auth map.
func TestPolicyFor_ReturnsAuthMap(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p := writeByn(t, "[scope]\n\n[auth]\nget = \"always\"\ndelete = \"none\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	policy, ok := d.policyFor(vault.DefaultVaultName, vault.Scope{
		Project: vault.DefaultProjectName,
		Env:     vault.DefaultEnvName,
	})
	if !ok {
		t.Fatal("policyFor returned ok=false, expected a policy")
	}
	if policy["get"] != "always" {
		t.Errorf("policy[get] = %q, want always", policy["get"])
	}
	if policy["delete"] != "none" {
		t.Errorf("policy[delete] = %q, want none", policy["delete"])
	}
}

// TestPolicyFor_UnknownVault_OkFalse verifies that policyFor returns ok=false
// for an unknown (uninitialized) vault name.
func TestPolicyFor_UnknownVault_OkFalse(t *testing.T) {
	d, _ := startTestDaemon(t)
	if _, ok := d.policyFor("unknown-vault", vault.Scope{}); ok {
		t.Error("policyFor should return ok=false for an unknown vault")
	}
}

// TestStrictest_AllCases verifies the strictest() helper covers all branches.
func TestStrictest_AllCases(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"always", "none", "always"},
		{"none", "always", "always"},
		{"always", "always", "always"},
		{"none", "none", "none"}, // both none: a is returned unchanged (none)
		{"none", "", ""},         // "none" < "": other wins
		{"", "none", ""},         // "": a stays (neutral over none)
		{"", "", ""},             // both neutral: a
		{"always", "", "always"},
		{"", "always", "always"},
	}
	for _, tc := range cases {
		got := strictest(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("strictest(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// ---- vk-MAC hand-forge detection: altered VKMAC field ----------------------

// TestPolicyFor_AlteredVKMACField_Ignored verifies that a record with a
// recognizably wrong VKMAC (altered hex bytes) is silently ignored.
func TestPolicyFor_AlteredVKMACField_Ignored(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "K", []byte("v"))

	p := writeByn(t, "[scope]\n\n[auth]\nget = \"none\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Directly alter the VKMAC field in the store (corrupt it).
	s, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	canon := trust.Canonicalize(p)
	for i := range s.Records {
		if s.Records[i].Path == canon {
			// Flip the first two hex bytes of the VKMAC.
			mac := s.Records[i].VKMAC
			if len(mac) >= 4 {
				b, _ := hex.DecodeString(mac[:4])
				b[0] ^= 0xff
				s.Records[i].VKMAC = hex.EncodeToString(b) + mac[2:]
			} else {
				s.Records[i].VKMAC = "deadbeef"
			}
			break
		}
	}
	if err := trust.Save(d.cfg.Dir, s); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get without password → auth_required (altered VKMAC record is ignored).
	err = c.Call(ipc.OpGet, ipc.GetReq{Name: "K"}, &ipc.GetResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("altered VKMAC: code = %v, want auth_required (record ignored)", code)
	}
}

// ---- structural ops: vault.delete with policy "delete=always" flag OFF -----

// TestPolicyVaultDelete_Always_FlagOff_Gated verifies that vault.delete is gated
// when policy says delete="always" even with per_action_auth OFF.
func TestPolicyVaultDelete_Always_FlagOff_Gated(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create a second vault to delete.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}

	// Trust a .byn on the DEFAULT vault with delete="always".
	// The vault.delete scope is vault.Scope{} (no project/env), so it
	// matches the vault-only record.
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// vault.delete on "default" vault: note that vault.delete passes vault.Scope{}
	// and the vault name being deleted. BUT the policy lookup uses the vault being
	// acted on, not necessarily the default vault. For vault.delete("acme"), the
	// policy lookup is against "acme" (which has no trusted .byn), so it falls
	// through to flag semantics (flag OFF → free). This tests the vault.delete
	// on the DEFAULT vault (which is blocked anyway), so we test project.delete
	// instead to exercise the "delete=always, flag off → gated" path.
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}

	// project.delete without creds → auth_required (policy always, flag off).
	err := c.Call(ipc.OpProjectDelete, ipc.ProjectDeleteReq{Name: "svc"}, &ipc.ProjectDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("project delete policy-always flag-off: code = %v, want auth_required", code)
	}
}

// ---- ad-hoc exec: .byn policy MUST NOT apply (blocking fix) ---------------
//
// Ad-hoc exec (req.Path == "") presents no .byn file. The [auth] exec="none"
// in a trusted .byn frees only that .byn's own exec contract (which carries
// an env allowlist). Ad-hoc exec injects the WHOLE scope with no allowlist —
// letting policy bypass credential verification here would be a security hole.
// execfetch.go calls authorizeActionAlways (not authorizeAction) to ensure
// policyFor is never consulted for ad-hoc exec.

// TestAdHocExec_PolicyNone_GarbagePassword_WrongPassword verifies that when
// per_action_auth is ON and a trusted .byn in the same scope has exec="none",
// ad-hoc exec with garbage password returns CodeWrongPassword (NOT free).
func TestAdHocExec_PolicyNone_GarbagePassword_WrongPassword(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Trust a .byn in the same scope with exec="none" — policy should NOT
	// bypass credential verification for ad-hoc exec.
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nexec = \"none\"\n", vault.DefaultVaultName, pw)

	// Ad-hoc exec (Path="") with garbage password → must be wrong_password,
	// never CodeValues — the policy must not apply.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     "", // ad-hoc: no .byn
		Command:  "any-cmd",
		Argv:     []string{"any-cmd"},
		Password: []byte("garbage-password"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("ad-hoc exec policy-none garbage pw: code = %v, want wrong_password (policy must not bypass auth)", code)
	}
}

// TestAdHocExec_PolicyNone_NoCreds_AuthRequired verifies that when per_action_auth
// is ON and a trusted .byn in the same scope has exec="none", ad-hoc exec with
// no credentials returns CodeAuthRequired (NOT free).
func TestAdHocExec_PolicyNone_NoCreds_AuthRequired(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Trust a .byn with exec="none" — must not affect the ad-hoc gate.
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nexec = \"none\"\n", vault.DefaultVaultName, pw)

	// Ad-hoc exec with no credentials → auth_required.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    "", // ad-hoc
		Command: "any-cmd",
		Argv:    []string{"any-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("ad-hoc exec policy-none no creds: code = %v, want auth_required (policy must not bypass auth)", code)
	}
}

// TestAdHocExec_PolicyNone_CorrectPassword_Values verifies that ad-hoc exec
// with the CORRECT password succeeds and injects vars (the gate is real, not
// blocked — correct auth still works).
func TestAdHocExec_PolicyNone_CorrectPassword_Values(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Trust a .byn with exec="none" — must not affect the ad-hoc gate.
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nexec = \"none\"\n", vault.DefaultVaultName, pw)

	// Ad-hoc exec with correct password → succeeds and injects all scope vars.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     "", // ad-hoc
		Command:  "any-cmd",
		Argv:     []string{"any-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("ad-hoc exec correct pw: want ok, got: %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "s3cret" {
		t.Errorf("SECRET = %q, want s3cret (ad-hoc injects whole scope)", m["SECRET"])
	}
}

// ---- trusted-path exec="none": env allowlist still enforced ---------------

// TestAuthExecNone_EnvAllowlistEnforced verifies that [auth] exec="none"
// frees any command BUT still injects ONLY the [exec] env allowlist — not the
// full scope. This pins the separation between auth policy and env filtering.
func TestAuthExecNone_EnvAllowlistEnforced(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "ALLOWED", []byte("allowed-val"))
	putVar(t, c, ipc.Scope{}, "BLOCKED", []byte("blocked-val"))

	// .byn with exec="none" + an explicit env allowlist of ["ALLOWED"] only.
	// Even though exec="none" frees the auth gate, only ALLOWED flows.
	byn := writeBynContent(t,
		"[scope]\n\n[exec]\nenv = [\"ALLOWED\"]\nactions = []\n\n[auth]\nexec = \"none\"\n")
	grantBynFile(t, c, byn, pw)

	// No creds — exec="none" means any command runs free.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "unlisted-cmd",
		Argv:    []string{"unlisted-cmd"},
		// No password.
	})
	if err != nil {
		t.Fatalf("exec=none: want free, got: %v", err)
	}
	m := valueMap(resp.Values)
	if m["ALLOWED"] != "allowed-val" {
		t.Errorf("ALLOWED = %q, want allowed-val", m["ALLOWED"])
	}
	if _, ok := m["BLOCKED"]; ok {
		t.Errorf("BLOCKED must not appear — exec=none does not bypass the env allowlist")
	}
}

// ---- vault.delete and vault.rename structural-op policy tests -------------
//
// Structural note: vault-level ops pass vault.Scope{} (no project/env) to
// authorizeAction. A .byn record with no [scope] project/env is a vault-only
// record (specificity=1) that matches ALL scopes within that vault, including
// Scope{}. So a (default,default)-equivalent record (project="", env="") does
// gate vault.delete and vault.rename on that vault.

// TestPolicyVaultDelete_Always_FlagOff_RealVaultOp verifies that vault.delete
// on a named vault is gated by delete="always" in a trusted .byn record on
// THAT vault, even with per_action_auth OFF.
func TestPolicyVaultDelete_Always_FlagOff_RealVaultOp(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create "acme" vault and unlock it.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}

	// Trust a .byn on "acme" with delete="always" (vault-only record: no
	// project/env → matches Scope{} used by vault.delete).
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{
		Path: p, Vault: "acme", Password: pw,
	}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant on acme: %v", err)
	}

	// vault.delete "acme" without creds → auth_required (policy always, flag off).
	err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme"}, &ipc.VaultDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("vault.delete policy-always flag-off no creds: code = %v, want auth_required", code)
	}

	// vault.delete "acme" with correct password → succeeds.
	if err := c.Call(ipc.OpVaultDelete, ipc.VaultDeleteReq{Name: "acme", Password: pw}, &ipc.VaultDeleteResp{}); err != nil {
		t.Fatalf("vault.delete policy-always with correct pw: %v", err)
	}
}

// TestPolicyVaultRename_Always_FlagOff_RealVaultOp verifies that vault.rename
// on a named vault is gated by update="always" in a trusted .byn record on
// THAT vault, even with per_action_auth OFF.
func TestPolicyVaultRename_Always_FlagOff_RealVaultOp(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create "acme" vault and unlock it.
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Name: "acme", Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("vault init acme: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Name: "acme", Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("vault unlock acme: %v", err)
	}

	// Trust a .byn on "acme" with update="always" (vault rename maps to "update").
	p := writeByn(t, "[scope]\n\n[auth]\nupdate = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{
		Path: p, Vault: "acme", Password: pw,
	}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant on acme: %v", err)
	}

	// vault.rename "acme" without creds → auth_required (policy always, flag off).
	err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{OldName: "acme", NewName: "brand"}, &ipc.VaultRenameResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("vault.rename policy-always flag-off no creds: code = %v, want auth_required", code)
	}

	// vault.rename "acme" with correct password → succeeds.
	if err := c.Call(ipc.OpVaultRename, ipc.VaultRenameReq{
		OldName: "acme", NewName: "brand", Password: pw,
	}, &ipc.VaultRenameResp{}); err != nil {
		t.Fatalf("vault.rename policy-always with correct pw: %v", err)
	}
}

// ---- env.delete maps to "delete" key -------------------------------------

// TestPolicyEnvDelete_Delete_None_FlagOn_Free verifies that [auth] delete="none"
// makes env.delete free even when per_action_auth is ON (env.delete maps to
// the "delete" action key, same as entry delete and env.clear).
func TestPolicyEnvDelete_Delete_None_FlagOn_Free(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Create a project and a non-default env so we have something to delete.
	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "svc", Name: "staging"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create staging: %v", err)
	}

	// Trust a .byn with delete="none" for the "svc" project scope.
	grantBynPolicy(t, d, c,
		"[scope]\nproject = \"svc\"\n\n[auth]\ndelete = \"none\"\n",
		vault.DefaultVaultName, pw)

	// env.delete without creds on the svc/staging scope → should succeed
	// (policy none for delete in this scope, even with flag ON).
	if err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{
		Project: "svc", Name: "staging",
	}, &ipc.EnvDeleteResp{}); err != nil {
		t.Fatalf("env.delete with delete=none: %v (expected free)", err)
	}
}

// TestPolicyEnvDelete_Delete_Always_FlagOff_Gated verifies that [auth]
// delete="always" gates env.delete even with per_action_auth OFF.
func TestPolicyEnvDelete_Delete_Always_FlagOff_Gated(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	if err := c.Call(ipc.OpProjectCreate, ipc.ProjectCreateReq{Name: "svc"}, &ipc.ProjectCreateResp{}); err != nil {
		t.Fatalf("project create: %v", err)
	}
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "svc", Name: "staging"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create staging: %v", err)
	}

	// Vault-only record with delete="always" (no project/env → matches any
	// scope within this vault, including svc/staging).
	p := writeByn(t, "[scope]\n\n[auth]\ndelete = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// env.delete without creds → auth_required (policy always, flag off).
	err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{
		Project: "svc", Name: "staging",
	}, &ipc.EnvDeleteResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("env.delete policy-always flag-off: code = %v, want auth_required", code)
	}

	// With correct password → succeeds.
	if err := c.Call(ipc.OpEnvDelete, ipc.EnvDeleteReq{
		Project: "svc", Name: "staging", Password: pw,
	}, &ipc.EnvDeleteResp{}); err != nil {
		t.Fatalf("env.delete policy-always with correct pw: %v", err)
	}
}

// ---- overwrite-put maps to "update": flag-off enforcement ------------------

// TestPolicyPut_Update_Always_FlagOff_NoCreds_AuthRequired verifies that
// [auth] update="always" gates overwrite-put even with per_action_auth OFF
// when no credentials are supplied.
func TestPolicyPut_Update_Always_FlagOff_NoCreds_AuthRequired(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v1"))

	// Trust a .byn with update="always".
	p := writeByn(t, "[scope]\n\n[auth]\nupdate = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Overwrite without creds → auth_required (policy always, even though flag is off).
	err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2")}, &ipc.PutResp{})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("overwrite flag-off policy-always no creds: code = %v, want auth_required", code)
	}
}

// TestPolicyPut_Update_Always_FlagOff_WrongPassword_Rejected verifies that a
// wrong password is rejected under update="always" even with per_action_auth OFF.
func TestPolicyPut_Update_Always_FlagOff_WrongPassword_Rejected(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v1"))

	p := writeByn(t, "[scope]\n\n[auth]\nupdate = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Overwrite with wrong password → wrong_password (not free).
	err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2"), Password: []byte("wrong")}, &ipc.PutResp{})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("overwrite flag-off policy-always wrong pw: code = %v, want wrong_password", code)
	}
}

// TestPolicyPut_Update_Always_FlagOff_CorrectPassword_Overwrites verifies that
// a correct password succeeds for overwrite-put under update="always" flag-off.
func TestPolicyPut_Update_Always_FlagOff_CorrectPassword_Overwrites(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v1"))

	p := writeByn(t, "[scope]\n\n[auth]\nupdate = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Overwrite with correct password → succeeds.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2"), Password: pw}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite flag-off policy-always correct pw: %v", err)
	}

	// Confirm new value (get is not gated, flag is off and no get policy).
	var resp ipc.GetResp
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY"}, &resp); err != nil {
		t.Fatalf("get after overwrite: %v", err)
	}
	if string(resp.Value) != "v2" {
		t.Errorf("value = %q, want v2", resp.Value)
	}
}

// TestPolicyPut_Update_Always_FlagOff_InsertStaysFree verifies that with
// update="always" and flag OFF, inserting a NEW name remains free — the
// policy only gates overwrites, not inserts.
func TestPolicyPut_Update_Always_FlagOff_InsertStaysFree(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Trust a .byn with update="always" before any insert.
	p := writeByn(t, "[scope]\n\n[auth]\nupdate = \"always\"\n")
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Insert a brand-new name without any creds → must succeed (insert stays free).
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "NEW_KEY", Value: []byte("val")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("insert with update=always flag-off: %v (insert must stay free)", err)
	}
}

// ---- overwrite-put maps to "update" ----------------------------------------

// TestPolicyPut_Update_None_FlagOn_Free verifies that [auth] update="none"
// makes overwrite-put free even when per_action_auth is ON.
func TestPolicyPut_Update_None_FlagOn_Free(t *testing.T) {
	d, c := startPerActionDaemonWithClient(t) // flag ON
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	putVar(t, c, ipc.Scope{}, "KEY", []byte("v1"))

	// Trust a .byn with update="none".
	grantBynPolicy(t, d, c, "[scope]\n\n[auth]\nupdate = \"none\"\n", vault.DefaultVaultName, pw)

	// Overwrite without creds — should succeed (policy none for update).
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "KEY", Value: []byte("v2")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("overwrite with update=none: %v (expected free)", err)
	}

	// Confirm new value.
	var resp ipc.GetResp
	// Need password since get is not set to none.
	if err := c.Call(ipc.OpGet, ipc.GetReq{Name: "KEY", Password: pw}, &resp); err != nil {
		t.Fatalf("get after overwrite: %v", err)
	}
	if string(resp.Value) != "v2" {
		t.Errorf("value = %q, want v2", resp.Value)
	}
}
