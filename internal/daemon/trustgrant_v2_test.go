package daemon

// trustgrant_v2_test.go — tests for NU-2 Task 3 grant-path v2 behavior:
//   - putTrustRecordWithKey stores ALL v2 fields (snapshot, actions, auth, scope).
//   - Malformed TOML at grant time → CodeBadRequest naming the parse error,
//     trust store untouched.
//   - Invalid [auth] at grant time → refused (CodeBadRequest).
//   - Invalid [exec] actions at grant time → refused (CodeBadRequest).
//   - Invalid [aliases] at grant time → refused (CodeBadRequest).
//   - Aliases stored in trust record and carried in response.
//   - Bulk: one malformed file among several → per-file error, others granted.
//   - byn.write+trust path stores v2.
//   - changed message in exec-fetch includes "trust diff".
//   - TrustGrantResp and TrustGrantResult carry the policy fields.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// ---- v2 field storage -------------------------------------------------------

// TestTrustGrant_V2_FieldsStored verifies that granting a well-formed .byn
// records all v2 fields: snapshot equals the file body, actions and auth are
// parsed from [exec] and [auth], scope mirrors [scope].
func TestTrustGrant_V2_FieldsStored(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	const body = `[scope]
vault   = "work"
project = "svc"
env     = "prod"

[exec]
actions = ["pnpm run start", "make test"]

[auth]
get    = "always"
delete = "always"
`
	p := writeByn(t, body)

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Vault: "default", Password: pw}, &resp); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Verify via trust.Load that every v2 field was persisted.
	rec, ok, err := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("record not found after grant")
	}
	if rec.Snapshot != body {
		t.Errorf("Snapshot != body:\n got %q\nwant %q", rec.Snapshot, body)
	}
	if rec.MTimeUnixNano == 0 {
		t.Error("MTimeUnixNano should be non-zero after grant")
	}
	if len(rec.Actions) != 2 || rec.Actions[0] != "pnpm run start" || rec.Actions[1] != "make test" {
		t.Errorf("Actions = %v, want [pnpm run start, make test]", rec.Actions)
	}
	if rec.Auth["get"] != "always" || rec.Auth["delete"] != "always" {
		t.Errorf("Auth = %v, want {get:always, delete:always}", rec.Auth)
	}
	if rec.ScopeVault != "work" || rec.ScopeProject != "svc" || rec.ScopeEnv != "prod" {
		t.Errorf("Scope = %s/%s/%s, want work/svc/prod", rec.ScopeVault, rec.ScopeProject, rec.ScopeEnv)
	}
	// IsV2 must be true.
	if !rec.IsV2() {
		t.Error("record should be v2 after grant")
	}
	// Response policy fields should be populated.
	if len(resp.Actions) != 2 {
		t.Errorf("resp.Actions = %v, want 2 items", resp.Actions)
	}
	if resp.Auth == nil || resp.Auth["get"] != "always" {
		t.Errorf("resp.Auth = %v, want {get:always, delete:always}", resp.Auth)
	}
}

// TestTrustGrant_V2_ActionsWildcard verifies that a .byn with [exec] actions =
// "*" is stored correctly and the response flags ActionsWildcard=true.
func TestTrustGrant_V2_ActionsWildcard(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p := writeByn(t, "[scope]\nproject = \"svc\"\n\n[exec]\nactions = \"*\"\n")

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &resp); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if !resp.ActionsWildcard {
		t.Error("ActionsWildcard should be true for actions = \"*\"")
	}
	rec, ok, err := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if len(rec.Actions) != 1 || rec.Actions[0] != "*" {
		t.Errorf("rec.Actions = %v, want [*]", rec.Actions)
	}
}

// TestTrustGrant_V2_NoActions verifies that a .byn with no [exec] actions
// stores an empty (nil) Actions slice and response.Actions is empty.
func TestTrustGrant_V2_NoActions(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p := writeByn(t, "[scope]\nproject = \"svc\"\n")

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &resp); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if resp.ActionsWildcard {
		t.Error("ActionsWildcard should be false when no actions declared")
	}
	if len(resp.Actions) != 0 {
		t.Errorf("Actions should be empty, got %v", resp.Actions)
	}
	rec, ok, err := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if len(rec.Actions) != 0 {
		t.Errorf("rec.Actions should be empty, got %v", rec.Actions)
	}
}

// ---- malformed TOML refused at grant time -----------------------------------

// TestTrustGrant_MalformedToml_Refused verifies that a syntactically invalid
// .byn is refused at grant time with CodeBadRequest naming the parse error.
// The trust store must remain untouched (the file should NOT be in the store).
func TestTrustGrant_MalformedToml_Refused(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p := writeByn(t, "not toml [[[")

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request for malformed TOML", code)
	}
	// Error message must mention the parse failure.
	msg := errMsg(t, err)
	if !strings.Contains(strings.ToLower(msg), "malformed") {
		t.Errorf("error message %q should mention malformed", msg)
	}
	// Trust store must be untouched.
	_, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if ok {
		t.Fatal("malformed .byn should NOT be recorded in the trust store")
	}
}

// TestTrustGrant_InvalidAuth_Refused verifies that a .byn with an invalid
// [auth] value (e.g. unknown key) is refused at grant time with CodeBadRequest.
func TestTrustGrant_InvalidAuth_Refused(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Unknown key "launch" in [auth].
	p := writeByn(t, "[scope]\nproject = \"svc\"\n\n[auth]\nlaunch = \"always\"\n")

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request for invalid [auth]", code)
	}
	// Trust store must be untouched.
	_, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if ok {
		t.Fatal("invalid [auth] .byn should NOT be recorded in the trust store")
	}
}

// ---- bulk: one malformed, others succeed ------------------------------------

// TestTrustGrantBulk_OneMalformed_OthersSucceed verifies the bulk grant
// per-file behavior: a malformed file reports an error in its result but
// the other files in the batch are still trusted.
func TestTrustGrantBulk_OneMalformed_OthersSucceed(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p1 := writeByn(t, "[scope]\nproject = \"svc1\"\n")
	pMalformed := writeByn(t, "not toml [[[")
	p3 := writeByn(t, "[scope]\nproject = \"svc3\"\n")

	var resp ipc.TrustGrantBulkResp
	if err := c.Call(ipc.OpTrustGrantBulk,
		ipc.TrustGrantBulkReq{Paths: []string{p1, pMalformed, p3}, Password: pw}, &resp); err != nil {
		t.Fatalf("bulk grant: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("got %d results, want 3", len(resp.Results))
	}
	// p1: should succeed.
	if resp.Results[0].Error != "" {
		t.Errorf("p1 should succeed, got error: %s", resp.Results[0].Error)
	}
	// pMalformed: should report an error.
	if resp.Results[1].Error == "" {
		t.Error("malformed .byn should report an error in its result")
	}
	if !strings.Contains(strings.ToLower(resp.Results[1].Error), "malformed") {
		t.Errorf("error %q should mention malformed", resp.Results[1].Error)
	}
	// p3: should succeed.
	if resp.Results[2].Error != "" {
		t.Errorf("p3 should succeed, got error: %s", resp.Results[2].Error)
	}
	// p1 and p3 should be in the trust store; pMalformed should NOT.
	if !bynTrusted(t, d, p1, "[scope]\nproject = \"svc1\"\n") {
		t.Error("p1 should be trusted")
	}
	if !bynTrusted(t, d, p3, "[scope]\nproject = \"svc3\"\n") {
		t.Error("p3 should be trusted")
	}
	_, malformedOK, _ := trust.Lookup(d.cfg.Dir, trust.Canonicalize(pMalformed))
	if malformedOK {
		t.Error("malformed .byn should NOT be in the trust store")
	}
}

// ---- byn.write + trust stores v2 -------------------------------------------

// TestBynWrite_TrustNow_StoresV2 verifies that the byn.write+trust path
// stores all v2 fields (snapshot, mtime, scope).
func TestBynWrite_TrustNow_StoresV2(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{
		Dir:      dir,
		Scope:    ipc.Scope{Project: "svc", Env: "prod"},
		EnvVars:  []string{"API_KEY"},
		Trust:    true,
		Password: pw,
	}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write+trust: %v", err)
	}
	if !resp.Trusted {
		t.Fatal("trusted should be true after Trust=true")
	}

	// Verify the v2 record was stored.
	canon := trust.Canonicalize(filepath.Join(dir, ".byn"))
	rec, ok, err := trust.Lookup(d.cfg.Dir, canon)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("record not found after byn.write+trust")
	}
	if rec.Snapshot == "" {
		t.Error("Snapshot should be populated after byn.write+trust")
	}
	if rec.MTimeUnixNano == 0 {
		t.Error("MTimeUnixNano should be non-zero after byn.write+trust")
	}
	if rec.ScopeProject != "svc" {
		t.Errorf("ScopeProject = %q, want svc", rec.ScopeProject)
	}
	if rec.ScopeEnv != "prod" {
		t.Errorf("ScopeEnv = %q, want prod", rec.ScopeEnv)
	}
	if !rec.IsV2() {
		t.Error("record should be v2 after byn.write+trust")
	}
}

// ---- changed message includes "trust diff" ----------------------------------

// TestChangedMessage_IncludesTrustDiff verifies that the exec-fetch error
// message for a changed .byn includes "trust diff" so users know to run
// `byn trust diff` (spec §1a notice).
func TestChangedMessage_IncludesTrustDiff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = [\"SECRET\"]\n")
	grantBynFile(t, c, byn, pw)

	// Modify the file so it registers as changed.
	if err := os.WriteFile(byn, []byte("[scope]\nproject = \"changed\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, fetchErr := execFetch(t, c, ipc.ExecFetchReq{Path: byn})
	if code := errCode(t, fetchErr); code != ipc.CodeTrustDenied {
		t.Fatalf("code = %v, want trust_denied", code)
	}
	msg := errMsg(t, fetchErr)
	if !strings.Contains(msg, "trust diff") {
		t.Errorf("changed message %q should contain 'trust diff'", msg)
	}
}

// ---- aliases stored in trust record -----------------------------------------

// TestTrustGrant_AliasesStored verifies that a .byn with a top-level [aliases]
// table has its aliases parsed, MAC-bound, and carried in the grant response.
func TestTrustGrant_AliasesStored(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	const body = `[scope]
project = "svc"

[exec]
actions = ["npm test", "npm run scrape"]

[aliases]
test = "npm test"
scrape = "npm run scrape"
`
	p := writeByn(t, body)

	var resp ipc.TrustGrantResp
	if err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &resp); err != nil {
		t.Fatalf("grant: %v", err)
	}

	// Response should carry the aliases.
	if len(resp.Aliases) != 2 {
		t.Errorf("resp.Aliases = %v, want 2 entries", resp.Aliases)
	}
	if resp.Aliases["test"] != "npm test" {
		t.Errorf("resp.Aliases[test] = %q, want npm test", resp.Aliases["test"])
	}
	if resp.Aliases["scrape"] != "npm run scrape" {
		t.Errorf("resp.Aliases[scrape] = %q, want npm run scrape", resp.Aliases["scrape"])
	}

	// Trust store record should also carry the aliases.
	rec, ok, err := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatal("record not found after grant")
	}
	if rec.Aliases["test"] != "npm test" || rec.Aliases["scrape"] != "npm run scrape" {
		t.Errorf("rec.Aliases = %v, want {test:npm test, scrape:npm run scrape}", rec.Aliases)
	}
}

// TestTrustGrant_InvalidActions_Refused verifies that a .byn with a bad action
// pattern (unknown placeholder type) is refused at grant with CodeBadRequest.
func TestTrustGrant_InvalidActions_Refused(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// "npm {{bogus}}" has an unknown placeholder type.
	p := writeByn(t, "[scope]\nproject = \"svc\"\n\n[exec]\nactions = [\"npm {{bogus}}\"]\n")

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request for invalid action pattern", code)
	}
	msg := errMsg(t, err)
	if !strings.Contains(strings.ToLower(msg), "actions") {
		t.Errorf("error message %q should mention actions", msg)
	}
	// Trust store must be untouched.
	_, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if ok {
		t.Fatal("invalid action .byn should NOT be recorded in the trust store")
	}
}

// TestTrustGrant_InvalidAlias_Refused verifies that a .byn with a malformed
// alias name is refused at grant time with CodeBadRequest.
func TestTrustGrant_InvalidAlias_Refused(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Alias name "-bad" starts with a dash — invalid.
	const body = "[scope]\nproject = \"svc\"\n\n[aliases]\n\"-bad\" = \"npm test\"\n"
	p := writeByn(t, body)

	err := c.Call(ipc.OpTrustGrant, ipc.TrustGrantReq{Path: p, Password: pw}, &ipc.TrustGrantResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request for invalid alias", code)
	}
	msg := errMsg(t, err)
	if !strings.Contains(strings.ToLower(msg), "aliases") && !strings.Contains(strings.ToLower(msg), "alias") {
		t.Errorf("error message %q should mention aliases", msg)
	}
	// Trust store must be untouched.
	_, ok, lerr := trust.Lookup(d.cfg.Dir, trust.Canonicalize(p))
	if lerr != nil {
		t.Fatalf("Lookup: %v", lerr)
	}
	if ok {
		t.Fatal("invalid alias .byn should NOT be recorded in the trust store")
	}
}

// ---- helpers ----------------------------------------------------------------

// errMsg extracts the error Message from an ipc.ErrResponse.
func errMsg(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var er *ipc.ErrResponse
	if !findErr(err, &er) {
		return err.Error()
	}
	return er.Message
}

// findErr extracts the ErrResponse if present; returns false otherwise.
func findErr(err error, target **ipc.ErrResponse) bool {
	var er *ipc.ErrResponse
	if extractErr(err, &er) {
		*target = er
		return true
	}
	return false
}

// extractErr tries to unwrap an ipc.ErrResponse from err.
func extractErr(err error, target **ipc.ErrResponse) bool {
	if err == nil {
		return false
	}
	type unwrapper interface{ Unwrap() error }
	for err != nil {
		if er, ok := err.(*ipc.ErrResponse); ok {
			*target = er
			return true
		}
		if uw, ok := err.(unwrapper); ok {
			err = uw.Unwrap()
		} else {
			return false
		}
	}
	return false
}
