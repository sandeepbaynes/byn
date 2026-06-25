package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// ─────────────────────────────────────────────────────────────────────────────
// byn.validate tests
// ─────────────────────────────────────────────────────────────────────────────

func TestBynValidate_OverSize(t *testing.T) {
	_, c := startTestDaemon(t)
	content := make([]byte, bynfile.MaxSize+1)
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for over-size content")
	}
	if resp.Errors[0].Section != "size" {
		t.Fatalf("section = %q, want \"size\"", resp.Errors[0].Section)
	}
}

func TestBynValidate_BadTOML(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: []byte("not toml [[[")}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for bad TOML")
	}
	if resp.Errors[0].Section != "toml" {
		t.Fatalf("section = %q, want \"toml\"", resp.Errors[0].Section)
	}
}

func TestBynValidate_BadAuth(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[auth]\nexec = \"invalid\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for invalid [auth]")
	}
	if resp.Errors[0].Section != "auth" {
		t.Fatalf("section = %q, want \"auth\"", resp.Errors[0].Section)
	}
}

func TestBynValidate_BadActions(t *testing.T) {
	_, c := startTestDaemon(t)
	// {{args}} in non-final position is invalid
	content := []byte("[exec]\nactions = [\"aws {{args}} s3\"]\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for invalid action pattern")
	}
	if resp.Errors[0].Section != "exec" {
		t.Fatalf("section = %q, want \"exec\"", resp.Errors[0].Section)
	}
}

func TestBynValidate_BadAliases(t *testing.T) {
	_, c := startTestDaemon(t)
	// Alias with placeholder in value is invalid
	content := []byte("[aliases]\ndeploy = \"kubectl apply {{args}}\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for alias with placeholder")
	}
	if resp.Errors[0].Section != "aliases" {
		t.Fatalf("section = %q, want \"aliases\"", resp.Errors[0].Section)
	}
}

func TestBynValidate_WarnEnvWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[exec]\nenv = \"*\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Errors)
	}
	if !hasWarning(resp.Warnings, "exec") {
		t.Fatal("expected warning for env wildcard in exec section")
	}
}

func TestBynValidate_WarnActionsWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[exec]\nactions = \"*\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Errors)
	}
	if !hasWarning(resp.Warnings, "exec") {
		t.Fatal("expected warning for actions wildcard")
	}
}

func TestBynValidate_WarnEmptyActions(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[scope]\nvault = \"default\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", resp.Errors)
	}
	found := false
	for _, w := range resp.Warnings {
		if w.Section == "exec" && strings.Contains(w.Message, "no [exec] actions") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'no [exec] actions' warning; got warnings: %v", resp.Warnings)
	}
}

func TestBynValidate_WarnArgsTail(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[exec]\nactions = [\"kubectl {{args}}\"]\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	found := false
	for _, w := range resp.Warnings {
		if strings.Contains(w.Message, "{{args}}") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected {{args}} warning; got: %v", resp.Warnings)
	}
}

func TestBynValidate_WarnShellInterpreter(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[exec]\nactions = [\"bash {{args}}\"]\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	found := false
	for _, w := range resp.Warnings {
		if strings.Contains(w.Message, "shell interpreter") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected shell interpreter warning; got: %v", resp.Warnings)
	}
}

func TestBynValidate_WarnAuthExecNone(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[auth]\nexec = \"none\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if !hasWarning(resp.Warnings, "auth") {
		t.Fatalf("expected auth warning for exec=none; got: %v", resp.Warnings)
	}
}

func TestBynValidate_WarnAuthGetNone(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[auth]\nget = \"none\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if !hasWarning(resp.Warnings, "auth") {
		t.Fatalf("expected auth warning for get=none; got: %v", resp.Warnings)
	}
}

func TestBynValidate_ValidFile_NoIssues(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"aws s3 ls\"]\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("expected no errors; got: %v", resp.Errors)
	}
	// Warnings may be present (env wildcard, shell interpreter, etc.), but there should be no errors.
}

// TestBynValidate_ParsedPopulatedOnZeroErrors: when there are zero errors, the
// Parsed field must be populated so the portal can carry the current entered
// values into the form/builder without a separate round-trip.
func TestBynValidate_ParsedPopulatedOnZeroErrors(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("[scope]\nvault = \"default\"\nproject = \"api\"\n\n[exec]\nenv = [\"API_KEY\"]\nactions = [\"make test\"]\nwritable = [\"~/Library/pnpm\", \"~/.cache/tool\"]\n\n[aliases]\ndeploy = \"kubectl apply\"\n\n[auth]\nexec = \"none\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("expected no errors; got: %v", resp.Errors)
	}
	if resp.Parsed == nil {
		t.Fatal("Parsed must be non-nil when there are zero errors")
	}
	if resp.Parsed.Scope.Vault != "default" {
		t.Errorf("Parsed.Scope.Vault = %q, want \"default\"", resp.Parsed.Scope.Vault)
	}
	if resp.Parsed.Scope.Project != "api" {
		t.Errorf("Parsed.Scope.Project = %q, want \"api\"", resp.Parsed.Scope.Project)
	}
	if len(resp.Parsed.Env) != 1 || resp.Parsed.Env[0] != "API_KEY" {
		t.Errorf("Parsed.Env = %v, want [API_KEY]", resp.Parsed.Env)
	}
	if len(resp.Parsed.Actions) != 1 || resp.Parsed.Actions[0] != "make test" {
		t.Errorf("Parsed.Actions = %v, want [make test]", resp.Parsed.Actions)
	}
	if len(resp.Parsed.Writable) != 2 || resp.Parsed.Writable[0] != "~/Library/pnpm" || resp.Parsed.Writable[1] != "~/.cache/tool" {
		t.Errorf("Parsed.Writable = %v, want [~/Library/pnpm ~/.cache/tool]", resp.Parsed.Writable)
	}
	if resp.Parsed.Aliases["deploy"] != "kubectl apply" {
		t.Errorf("Parsed.Aliases[deploy] = %q, want \"kubectl apply\"", resp.Parsed.Aliases["deploy"])
	}
	if resp.Parsed.Auth["exec"] != "none" {
		t.Errorf("Parsed.Auth[exec] = %q, want \"none\"", resp.Parsed.Auth["exec"])
	}
}

// TestBynValidate_ParsedNilOnErrors: when there are errors, Parsed must be nil.
func TestBynValidate_ParsedNilOnErrors(t *testing.T) {
	_, c := startTestDaemon(t)
	content := []byte("not toml [[[")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected errors for invalid TOML")
	}
	if resp.Parsed != nil {
		t.Error("Parsed must be nil when errors are present")
	}
}

// hasWarning is a helper that checks if any warning has the given section.
func hasWarning(warns []ipc.BynIssue, section string) bool {
	for _, w := range warns {
		if w.Section == section {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.simulate tests + cross-check with real exec gate
// ─────────────────────────────────────────────────────────────────────────────

// simulateAndExecCheck simulates the verdict and also runs a real exec.fetch
// to verify they agree. The exec.fetch call won't actually inject values (the
// vault may not have them) but it will agree on the auth/free verdict.
//
// This is the slice's key invariant test — simulate and enforcement must agree.
func simulateAndExecCheck(t *testing.T, c *ipc.Client, bynContent, cmdLine string, wantVerdict string) ipc.BynSimulateResp {
	t.Helper()
	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(bynContent),
		CommandLine: cmdLine,
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if simResp.Verdict != wantVerdict {
		t.Errorf("simulate verdict = %q, want %q (cmd=%q)", simResp.Verdict, wantVerdict, cmdLine)
	}
	return simResp
}

func TestBynSimulate_ExactMatch_FreeVerdict(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = [\"aws s3 ls\"]\n"
	cmdLine := "aws s3 ls"

	// Write and grant the file for exec.fetch cross-check.
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, cmdLine, "free")
	if simResp.MatchedKind != "action" {
		t.Errorf("MatchedKind = %q, want \"action\"", simResp.MatchedKind)
	}
	if simResp.MatchedAction != "aws s3 ls" {
		t.Errorf("MatchedAction = %q, want \"aws s3 ls\"", simResp.MatchedAction)
	}

	// Cross-check: exec.fetch with matching argv should succeed (free).
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"aws", "s3", "ls"}})
	if err != nil {
		t.Errorf("exec.fetch should be free but got: %v", err)
	}
}

func TestBynSimulate_PatternMatch_UUID(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = [\"myapp delete {{uuid}}\"]\n"
	cmdLine := "myapp delete 550e8400-e29b-41d4-a716-446655440000"

	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, cmdLine, "free")
	if simResp.MatchedKind != "action" {
		t.Errorf("MatchedKind = %q, want \"action\"", simResp.MatchedKind)
	}

	// Cross-check.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: p, Argv: []string{"myapp", "delete", "550e8400-e29b-41d4-a716-446655440000"},
	})
	if err != nil {
		t.Errorf("exec.fetch (uuid match): %v", err)
	}
}

func TestBynSimulate_AliasExpansionWithArgsTail_Free(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// deploy is an alias that expands to "kubectl apply -f"; the pattern
	// "kubectl apply -f {{args}}" allows it to run free.
	bynContent := "[exec]\nactions = [\"kubectl apply -f {{args}}\"]\n\n[aliases]\ndeploy = \"kubectl apply -f\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	// Simulate: "deploy prod.yaml" → alias expand → "kubectl apply -f prod.yaml"
	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(bynContent),
		CommandLine: "deploy prod.yaml",
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if simResp.Verdict != "free" {
		t.Errorf("simulate verdict = %q, want free (alias+args)", simResp.Verdict)
	}
	if simResp.MatchedAlias != "deploy" {
		t.Errorf("MatchedAlias = %q, want \"deploy\"", simResp.MatchedAlias)
	}
	// ResolvedArgv should be the expanded form.
	if len(simResp.ResolvedArgv) < 4 {
		t.Errorf("ResolvedArgv = %v, expected >=4 tokens", simResp.ResolvedArgv)
	}

	// Cross-check with exec.fetch alias path.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  p,
		Alias: "deploy",
		Argv:  []string{"prod.yaml"},
	})
	if err != nil {
		t.Errorf("exec.fetch alias (free): %v", err)
	}
}

func TestBynSimulate_AliasExtraArgsNoMatch_Auth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// deploy alias, but no action pattern covers the resolved form.
	bynContent := "[exec]\nactions = [\"kubectl get pods\"]\n\n[aliases]\ndeploy = \"kubectl apply\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	// "deploy -f prod.yaml" → "kubectl apply -f prod.yaml" — no match → auth
	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(bynContent),
		CommandLine: "deploy -f prod.yaml",
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}
	if simResp.Verdict != "auth" {
		t.Errorf("simulate verdict = %q, want auth", simResp.Verdict)
	}

	// Cross-check: exec.fetch with no password should require auth.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  p,
		Alias: "deploy",
		Argv:  []string{"-f", "prod.yaml"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Errorf("exec.fetch alias (auth): code = %v, want auth_required", code)
	}
}

func TestBynSimulate_WildcardActions_Free(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = \"*\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, "any-random-command --flag", "free")
	if simResp.MatchedKind != "wildcard" {
		t.Errorf("MatchedKind = %q, want \"wildcard\"", simResp.MatchedKind)
	}

	// Cross-check.
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"any-random-command", "--flag"}})
	if err != nil {
		t.Errorf("exec.fetch wildcard: %v", err)
	}
}

func TestBynSimulate_ExecAlways_Auth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = \"*\"\n\n[auth]\nexec = \"always\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, "any-cmd", "auth")
	if !strings.Contains(simResp.Reason, "always") {
		t.Errorf("Reason = %q, expected 'always' in reason", simResp.Reason)
	}

	// Cross-check: exec.fetch with no password → auth required.
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"any-cmd"}})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Errorf("exec.fetch exec=always: code = %v, want auth_required", code)
	}
}

func TestBynSimulate_ExecNone_Free(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[auth]\nexec = \"none\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, "any-cmd", "free")
	if simResp.MatchedKind != "wildcard" {
		t.Errorf("MatchedKind = %q, want \"wildcard\" for exec=none", simResp.MatchedKind)
	}

	// Cross-check: exec.fetch with no password → free (exec=none bypasses gate).
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"any-cmd"}})
	if err != nil {
		t.Errorf("exec.fetch exec=none: expected free, got: %v", err)
	}
}

func TestBynSimulate_Unmatched_Auth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = [\"aws s3 ls\"]\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, "kubectl get pods", "auth")
	if simResp.MatchedKind != "none" {
		t.Errorf("MatchedKind = %q, want \"none\" for unmatched", simResp.MatchedKind)
	}

	// Cross-check: exec.fetch → auth_required.
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"kubectl", "get", "pods"}})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Errorf("exec.fetch unmatched: code = %v, want auth_required", code)
	}
}

func TestBynSimulate_EmptyActions_Auth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[scope]\nvault = \"default\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	simResp := simulateAndExecCheck(t, c, bynContent, "ls -la", "auth")
	_ = simResp

	// Cross-check.
	_, err := execFetch(t, c, ipc.ExecFetchReq{Path: p, Argv: []string{"ls", "-la"}})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Errorf("exec.fetch empty actions: code = %v, want auth_required", code)
	}
}

func TestBynSimulate_InvalidContent_BadRequest(t *testing.T) {
	_, c := startTestDaemon(t)
	err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte("not toml [[["),
		CommandLine: "aws s3 ls",
	}, &ipc.BynSimulateResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("invalid content: code = %v, want bad_request", code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.read tests
// ─────────────────────────────────────────────────────────────────────────────

func TestBynRead_Trusted(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[scope]\nvault = \"default\"\n"
	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.TrustStatus != string(trust.VerifyTrusted) {
		t.Errorf("TrustStatus = %q, want \"trusted\"", resp.TrustStatus)
	}
	if string(resp.Content) != bynContent {
		t.Errorf("Content = %q, want %q", resp.Content, bynContent)
	}
	if resp.Path != trust.Canonicalize(p) {
		t.Errorf("Path = %q, want canonical", resp.Path)
	}
}

func TestBynRead_Untrusted(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	p := writeByn(t, "[scope]\n")
	// Never granted.
	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.TrustStatus != string(trust.VerifyUntrusted) {
		t.Errorf("TrustStatus = %q, want \"untrusted\"", resp.TrustStatus)
	}
}

func TestBynRead_Changed(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	p := writeByn(t, "[scope]\n")
	grantBynFile(t, c, p, pw)

	// Modify the file.
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("# modified\n")
	_ = f.Close()

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.TrustStatus != string(trust.VerifyChanged) {
		t.Errorf("TrustStatus = %q, want \"changed\"", resp.TrustStatus)
	}
}

func TestBynRead_SizeCap(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	// Write an oversized file.
	dir := t.TempDir()
	p := filepath.Join(dir, ".byn")
	content := make([]byte, bynfile.MaxSize+1)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}

	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &ipc.BynReadResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("oversize: code = %v, want bad_request", code)
	}
}

func TestBynRead_Missing(t *testing.T) {
	_, c := startTestDaemon(t)
	// A path whose final component is exactly ".byn" in an existing dir, but the
	// file is absent — this reaches the actual read (past the name guard), unlike
	// a "*.byn" name which the endpoint rejects up front (see TestBynRead_NonBynPath).
	missing := filepath.Join(t.TempDir(), ".byn")
	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: missing}, &ipc.BynReadResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("missing file: code = %v, want bad_request", code)
	}
	// The message must read as "not found" so the portal's dropdown loader
	// (studioLoadFromDir) treats an absent .byn as the normal blank case and
	// resets silently — distinct from an FDA/TCC read denial, which it surfaces
	// with the grant-Full-Disk-Access workflow. annotateReadErr leaves a
	// not-exist error unchanged on every OS.
	if msg := errMsg(t, err); !strings.Contains(msg, "no such file") {
		t.Errorf("missing-file message = %q, want it to contain %q", msg, "no such file")
	}
}

// TestBynRead_NonBynPath: byn.read must refuse any path whose final component
// is not exactly ".byn" — the endpoint must not act as an arbitrary file-read
// oracle (e.g. /etc/hosts, ~/.ssh/config).
func TestBynRead_NonBynPath(t *testing.T) {
	_, c := startTestDaemon(t)

	// Write a temp file with a non-.byn name so the rejection is about the
	// name, not a missing file.
	dir := t.TempDir()
	notByn := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(notByn, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: notByn}, &ipc.BynReadResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("non-.byn path: code = %v, want bad_request", code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BynWrite Content field tests
// ─────────────────────────────────────────────────────────────────────────────

func TestBynWrite_ContentVerbatim(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	// Write verbatim content with a custom action pattern.
	verbatim := "[scope]\nvault = \"default\"\n\n[exec]\nenv = [\"DB_URL\"]\nactions = [\"aws s3 ls\"]\n"
	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Content: []byte(verbatim)}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write with Content: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, ".byn"))
	if err != nil {
		t.Fatalf("read .byn: %v", err)
	}
	if string(body) != verbatim {
		t.Errorf("written content = %q, want verbatim %q", body, verbatim)
	}
}

func TestBynWrite_ContentValidationRefusal(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	// Invalid content (bad TOML) should be refused.
	err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{
		Dir:     dir,
		Content: []byte("not toml [[["),
	}, &ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("invalid content: code = %v, want bad_request", code)
	}
	// File must not have been written.
	if _, err := os.Stat(filepath.Join(dir, ".byn")); err == nil {
		t.Fatal(".byn was written despite invalid content")
	}
}

func TestBynWrite_ContentOversize_Refused(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	oversized := make([]byte, bynfile.MaxSize+1)
	err := c.Call(ipc.OpBynWrite, ipc.BynWriteReq{
		Dir:     dir,
		Content: oversized,
	}, &ipc.BynWriteResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("oversized: code = %v, want bad_request", code)
	}
}

func TestBynWrite_ContentAndTrust(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	content := "[scope]\nvault = \"default\"\n\n[exec]\nactions = [\"aws s3 ls\"]\n"
	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{Dir: dir, Content: []byte(content), Trust: true, Password: pw}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write+trust with Content: %v", err)
	}
	if !resp.Trusted {
		t.Fatal("expected Trusted=true after Content+Trust write")
	}
	body, _ := os.ReadFile(resp.Path)
	if string(body) != content {
		t.Errorf("content not verbatim after trust write")
	}
}

// TestBynWrite_ContentTrust_VaultFromParsedContent verifies that when Content
// is provided with Trust=true, the daemon derives the target vault from the
// parsed [scope].vault field in the content — not from the req.Scope.Vault
// client field (which the studio omits in raw/verbatim mode).
//
// The test writes verbatim content whose [scope].vault = "default" (the only
// vault the daemon has, which is unlocked) without sending any Scope in the
// request. The trust record must be stored under the "default" vault.
func TestBynWrite_ContentTrust_VaultFromParsedContent(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	dir := t.TempDir()

	// Verbatim content declares vault = "default" in [scope].
	// We deliberately do NOT set req.Scope — the daemon must derive it.
	content := "[scope]\nvault = \"default\"\n\n[exec]\nactions = [\"make test\"]\n"
	var resp ipc.BynWriteResp
	req := ipc.BynWriteReq{
		Dir:      dir,
		Content:  []byte(content),
		Trust:    true,
		Password: pw,
		// Scope deliberately left zero — daemon must use content's [scope].vault.
	}
	if err := c.Call(ipc.OpBynWrite, req, &resp); err != nil {
		t.Fatalf("byn write+trust (content vault targeting): %v", err)
	}
	if !resp.Trusted {
		t.Fatal("expected Trusted=true")
	}

	// Load the trust store and confirm the record's Vault field is "default".
	ts, err := trust.Load(d.cfg.Dir)
	if err != nil {
		t.Fatalf("trust.Load: %v", err)
	}
	canon := trust.Canonicalize(resp.Path)
	var rec *trust.Record
	for i := range ts.Records {
		if ts.Records[i].Path == canon {
			rec = &ts.Records[i]
			break
		}
	}
	if rec == nil {
		t.Fatalf("trust record not found for %s", canon)
	}
	if rec.Vault != "default" {
		t.Errorf("trust record Vault = %q, want \"default\" (derived from parsed content)", rec.Vault)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// config.get / config.set tests
// ─────────────────────────────────────────────────────────────────────────────

func TestConfigGet_AbsentFile_ReturnsPathEmptyContent(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	var resp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp); err != nil {
		t.Fatalf("config.get: %v", err)
	}
	if resp.Path == "" {
		t.Fatal("Path must be non-empty even when file is absent")
	}
	if len(resp.Content) != 0 {
		t.Fatalf("Content should be empty for absent file; got %d bytes", len(resp.Content))
	}
}

func TestConfigSet_InvalidTOML_Refused(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte("not toml [[["),
	}, &ipc.ConfigSetResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("invalid TOML: code = %v, want bad_request", code)
	}
}

func TestConfigSet_InvalidRange_Refused(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	// Port out of range.
	err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte("[ui]\nport = 99999\n"),
	}, &ipc.ConfigSetResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("out-of-range port: code = %v, want bad_request", code)
	}
}

func TestConfigSet_Valid_FileWrittenAndReloadApplied(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	// config.get to check current state.
	var getResp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &getResp); err != nil {
		t.Fatalf("config.get: %v", err)
	}

	// Set config with a non-default ui port — exercises the full write+reload cycle.
	newContent := "[ui]\nenabled = true\nport = 2968\n"
	var setResp ipc.ConfigSetResp
	if err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte(newContent),
	}, &setResp); err != nil {
		t.Fatalf("config.set: %v", err)
	}

	// config.get after set should return the new content.
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &getResp); err != nil {
		t.Fatalf("config.get after set: %v", err)
	}
	if !strings.Contains(string(getResp.Content), "2968") {
		t.Errorf("config content after set does not contain port 2968; got: %s", getResp.Content)
	}
}

func TestConfigSet_InvalidTOML_FileUnchanged(t *testing.T) {
	// When config.set receives invalid TOML, the config file must remain
	// byte-identical (not written).
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	// First, set a valid config.
	validContent := "[ui]\nport = 2968\n"
	var setResp ipc.ConfigSetResp
	if err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte(validContent),
	}, &setResp); err != nil {
		t.Fatalf("config.set valid: %v", err)
	}

	// Read the file to get its bytes.
	var getResp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &getResp); err != nil {
		t.Fatalf("config.get after valid set: %v", err)
	}
	originalBytes := getResp.Content

	// Now try to set invalid TOML; should be rejected.
	err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte("not toml [[["),
	}, &ipc.ConfigSetResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("invalid TOML: code = %v, want bad_request", code)
	}

	// config.get again; file must be byte-identical.
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &getResp); err != nil {
		t.Fatalf("config.get after rejected set: %v", err)
	}
	if !bytes.Equal(getResp.Content, originalBytes) {
		t.Errorf("file was modified after invalid set; was %q, now %q",
			string(originalBytes), string(getResp.Content))
	}
}

func TestBynValidate_NoUpdateDeleteWarnings(t *testing.T) {
	// update=none and delete=none should appear as warnings in byn.validate.
	_, c := startTestDaemon(t)

	content := []byte("[auth]\nupdate = \"none\"\ndelete = \"none\"\n")
	var resp ipc.BynValidateResp
	if err := c.Call(ipc.OpBynValidate, ipc.BynValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("byn.validate: %v", err)
	}

	// Expect warnings for both update=none and delete=none.
	updateWarn := false
	deleteWarn := false
	for _, w := range resp.Warnings {
		if w.Section == "auth" && strings.Contains(w.Message, "update") {
			updateWarn = true
		}
		if w.Section == "auth" && strings.Contains(w.Message, "delete") {
			deleteWarn = true
		}
	}
	if !updateWarn {
		t.Fatalf("expected update=none warning; got: %v", resp.Warnings)
	}
	if !deleteWarn {
		t.Fatalf("expected delete=none warning; got: %v", resp.Warnings)
	}
}

func TestBynSimulate_AuditEventEmitted(t *testing.T) {
	// byn.simulate should emit an audit event with op="byn.simulate" and
	// outcome="ok".
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	bynContent := "[exec]\nactions = [\"aws s3 ls\"]\n"
	cmdLine := "aws s3 ls"

	p := writeByn(t, bynContent)
	grantBynFile(t, c, p, pw)

	var simResp ipc.BynSimulateResp
	if err := c.Call(ipc.OpBynSimulate, ipc.BynSimulateReq{
		Content:     []byte(bynContent),
		CommandLine: cmdLine,
	}, &simResp); err != nil {
		t.Fatalf("byn.simulate: %v", err)
	}

	// Check the audit tail for the operation.
	var auditResp ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &auditResp); err != nil {
		t.Fatalf("audit.tail: %v", err)
	}

	// Find the byn.simulate event in the tail.
	found := false
	for _, evt := range auditResp.Events {
		if evt.Op == string(ipc.OpBynSimulate) {
			found = true
			if evt.Outcome != audit.OutcomeOK {
				t.Errorf("byn.simulate outcome = %q, want %q", evt.Outcome, audit.OutcomeOK)
			}
			break
		}
	}
	if !found {
		t.Fatalf("byn.simulate event not found in audit tail; events: %v", auditResp.Events)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.read symlink-bypass hardening test
// ─────────────────────────────────────────────────────────────────────────────

// TestBynRead_SymlinkNamedByn ensures that a symlink whose raw basename is
// ".byn" but whose RESOLVED (canonical) target has a different basename is
// rejected.  Without the fix (checking Base of the resolved path rather than
// the raw path), an attacker could create:
//
//	ln -s ~/.ssh/id_rsa /tmp/evil/.byn
//
// and call byn.read with path=/tmp/evil/.byn — the raw basename passes the
// original guard, but the resolved path is id_rsa.  The daemon must refuse.
func TestBynRead_SymlinkNamedByn_IsRefused(t *testing.T) {
	_, c := startTestDaemon(t)

	// Create a real file with a non-.byn name (simulates ~/.ssh/id_rsa).
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(secretFile, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a symlink named ".byn" pointing at the secret file.
	symlinkDir := t.TempDir()
	symlinkPath := filepath.Join(symlinkDir, ".byn")
	if err := os.Symlink(secretFile, symlinkPath); err != nil {
		t.Skipf("cannot create symlink (unsupported on this OS): %v", err)
	}

	// byn.read should refuse: raw basename is ".byn" but canonical basename
	// is "id_rsa" — the check must be on the resolved path.
	err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: symlinkPath}, &ipc.BynReadResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("symlink-named-.byn-to-non-.byn: code = %v, want bad_request (symlink bypass must be blocked)", code)
	}
}

// TestBynRead_SymlinkToRealByn ensures that a symlink named ".byn" pointing
// at a REAL ".byn" file is still accepted (the canonical basename IS ".byn").
func TestBynRead_SymlinkToRealByn_IsAllowed(t *testing.T) {
	_, c := startTestDaemon(t)

	// Create a real .byn file.
	bynContent := "[scope]\nvault = \"default\"\n"
	realDir := t.TempDir()
	realByn := filepath.Join(realDir, ".byn")
	if err := os.WriteFile(realByn, []byte(bynContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a second directory containing a symlink named ".byn" → the real file.
	linkDir := t.TempDir()
	symlinkPath := filepath.Join(linkDir, ".byn")
	if err := os.Symlink(realByn, symlinkPath); err != nil {
		t.Skipf("cannot create symlink (unsupported on this OS): %v", err)
	}

	// byn.read via the symlink path should succeed (canonical basename is ".byn").
	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: symlinkPath}, &resp); err != nil {
		t.Fatalf("byn.read via symlink to real .byn: %v", err)
	}
	if string(resp.Content) != bynContent {
		t.Errorf("content via symlink = %q, want %q", resp.Content, bynContent)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// byn.read Parsed payload tests
// ─────────────────────────────────────────────────────────────────────────────

// TestBynRead_ParsedPayload_CleanParse: when content parses cleanly, Parsed
// is populated with the structured fields and ParseError is empty.
func TestBynRead_ParsedPayload_CleanParse(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	content := "[scope]\nvault = \"default\"\nproject = \"api\"\n\n[exec]\nenv = [\"API_KEY\", \"DB_URL\"]\nactions = [\"make test\"]\n\n[aliases]\ndeploy = \"kubectl apply\"\n\n[auth]\nexec = \"none\"\n"
	p := writeByn(t, content)

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}

	if resp.Parsed == nil {
		t.Fatal("expected Parsed to be non-nil for clean-parse content")
	}
	if resp.ParseError != "" {
		t.Errorf("ParseError = %q, want empty for clean parse", resp.ParseError)
	}
	if resp.Parsed.Scope.Vault != "default" {
		t.Errorf("Parsed.Scope.Vault = %q, want \"default\"", resp.Parsed.Scope.Vault)
	}
	if resp.Parsed.Scope.Project != "api" {
		t.Errorf("Parsed.Scope.Project = %q, want \"api\"", resp.Parsed.Scope.Project)
	}
	if len(resp.Parsed.Env) != 2 || resp.Parsed.Env[0] != "API_KEY" || resp.Parsed.Env[1] != "DB_URL" {
		t.Errorf("Parsed.Env = %v, want [API_KEY DB_URL]", resp.Parsed.Env)
	}
	if resp.Parsed.EnvWildcard {
		t.Error("Parsed.EnvWildcard should be false for explicit list")
	}
	if len(resp.Parsed.Actions) != 1 || resp.Parsed.Actions[0] != "make test" {
		t.Errorf("Parsed.Actions = %v, want [make test]", resp.Parsed.Actions)
	}
	if resp.Parsed.ActionsWildcard {
		t.Error("Parsed.ActionsWildcard should be false for explicit list")
	}
	if resp.Parsed.Aliases["deploy"] != "kubectl apply" {
		t.Errorf("Parsed.Aliases[deploy] = %q, want \"kubectl apply\"", resp.Parsed.Aliases["deploy"])
	}
	if resp.Parsed.Auth["exec"] != "none" {
		t.Errorf("Parsed.Auth[exec] = %q, want \"none\"", resp.Parsed.Auth["exec"])
	}
}

// TestBynRead_ParsedPayload_EnvWildcard: env="*" sets EnvWildcard=true.
func TestBynRead_ParsedPayload_EnvWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	content := "[exec]\nenv = \"*\"\n"
	p := writeByn(t, content)

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.Parsed == nil {
		t.Fatal("expected Parsed to be non-nil")
	}
	if !resp.Parsed.EnvWildcard {
		t.Error("Parsed.EnvWildcard should be true for env=\"*\"")
	}
}

// TestBynRead_ParsedPayload_ParseErrorFallback: when content is invalid TOML,
// Parsed is nil and ParseError is non-empty.
func TestBynRead_ParsedPayload_ParseErrorFallback(t *testing.T) {
	_, c := startTestDaemon(t)

	dir := t.TempDir()
	p := filepath.Join(dir, ".byn")
	// Write invalid TOML directly (bypass byn.write validation).
	if err := os.WriteFile(p, []byte("not valid toml [[["), 0o600); err != nil {
		t.Fatal(err)
	}

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read: %v", err)
	}
	if resp.Parsed != nil {
		t.Error("Parsed should be nil when content fails to parse")
	}
	if resp.ParseError == "" {
		t.Error("ParseError should be non-empty when content fails to parse")
	}
}

// TestBynRead_ParsedPayload_OmittedWhenAbsent: Parsed and ParseError are both
// absent when the file is empty (zero-byte content).
func TestBynRead_ParsedPayload_OmittedWhenAbsent(t *testing.T) {
	_, c := startTestDaemon(t)

	dir := t.TempDir()
	p := filepath.Join(dir, ".byn")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	var resp ipc.BynReadResp
	if err := c.Call(ipc.OpBynRead, ipc.BynReadReq{Path: p}, &resp); err != nil {
		t.Fatalf("byn.read empty file: %v", err)
	}
	if resp.Parsed != nil {
		t.Error("Parsed should be nil for empty content")
	}
	if resp.ParseError != "" {
		t.Errorf("ParseError = %q, want empty for empty content", resp.ParseError)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// config.get Parsed payload tests
// ─────────────────────────────────────────────────────────────────────────────

// TestConfigGet_ParsedDefaults: when the config file is absent, Parsed must
// carry the Default() values so the visual settings editor pre-populates correctly.
func TestConfigGet_ParsedDefaults(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	var resp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp); err != nil {
		t.Fatalf("config.get: %v", err)
	}
	// Absent file → Parsed must be non-nil (populated from Default()).
	if resp.Parsed == nil {
		t.Fatal("Parsed must be non-nil for absent config (defaults apply)")
	}
	if resp.ParseError != "" {
		t.Errorf("ParseError = %q, want empty for defaults", resp.ParseError)
	}
	// Verify the default values are correct.
	if !resp.Parsed.UIEnabled {
		t.Error("default UIEnabled should be true")
	}
	if resp.Parsed.UIPort != 2967 {
		t.Errorf("default UIPort = %d, want 2967", resp.Parsed.UIPort)
	}
	if resp.Parsed.IdleTimeout == "" {
		t.Error("default IdleTimeout must not be empty")
	}
}

// TestConfigGet_ParsedValues: when a valid config file is present, Parsed
// must reflect the parsed values.
func TestConfigGet_ParsedValues(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Write a config with non-default values.
	content := "[ui]\nenabled = false\nport = 3000\n\n[daemon]\nidle_timeout = \"5m\"\n"
	var setResp ipc.ConfigSetResp
	if err := c.Call(ipc.OpConfigSet, ipc.ConfigSetReq{
		Content: []byte(content),
	}, &setResp); err != nil {
		t.Fatalf("config.set: %v", err)
	}
	_ = d // ensure daemon ref is kept

	var resp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp); err != nil {
		t.Fatalf("config.get after set: %v", err)
	}
	if resp.Parsed == nil {
		t.Fatal("Parsed must be non-nil for a valid config file")
	}
	if resp.ParseError != "" {
		t.Errorf("ParseError = %q, want empty", resp.ParseError)
	}
	if resp.Parsed.UIEnabled {
		t.Error("UIEnabled should be false after config.set")
	}
	if resp.Parsed.UIPort != 3000 {
		t.Errorf("UIPort = %d, want 3000", resp.Parsed.UIPort)
	}
	if resp.Parsed.IdleTimeout != "5m0s" {
		t.Errorf("IdleTimeout = %q, want %q", resp.Parsed.IdleTimeout, "5m0s")
	}
}

// TestConfigGet_ParseError: when the config file contains corrupt TOML, Parsed
// must be nil and ParseError must be non-empty so the portal can fall back to
// raw mode with a notice (mirrors the byn.read pattern).
func TestConfigGet_ParseError(t *testing.T) {
	d, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	// Write a corrupt config file directly (bypassing the daemon's own
	// validation gate) to simulate external corruption.
	cfgPath := filepath.Join(d.cfg.Dir, "config")
	if err := os.WriteFile(cfgPath, []byte("not valid toml [[["), 0o600); err != nil {
		t.Fatalf("write corrupt config: %v", err)
	}

	var resp ipc.ConfigGetResp
	if err := c.Call(ipc.OpConfigGet, ipc.ConfigGetReq{}, &resp); err != nil {
		t.Fatalf("config.get: %v", err)
	}
	if resp.Parsed != nil {
		t.Error("Parsed must be nil for corrupt config")
	}
	if resp.ParseError == "" {
		t.Error("ParseError must be non-empty for corrupt config")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// config.validate tests
// ─────────────────────────────────────────────────────────────────────────────

// TestConfigValidate_ValidContent: valid TOML → Errors empty, Parsed populated.
func TestConfigValidate_ValidContent(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	content := []byte("[ui]\nenabled = true\nport = 2967\n\n[daemon]\nidle_timeout = \"5m\"\n")
	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}
	if len(resp.Errors) != 0 {
		t.Fatalf("expected no errors for valid content; got: %v", resp.Errors)
	}
	if resp.Parsed == nil {
		t.Fatal("Parsed must be non-nil for valid content")
	}
	if resp.Parsed.UIPort != 2967 {
		t.Errorf("Parsed.UIPort = %d, want 2967", resp.Parsed.UIPort)
	}
	if resp.Parsed.IdleTimeout != "5m0s" {
		t.Errorf("Parsed.IdleTimeout = %q, want \"5m0s\"", resp.Parsed.IdleTimeout)
	}
}

// TestConfigValidate_PerActionAuthRejected: per_action_auth in config must be
// rejected as an unknown key — proving the strict parser enforces full removal.
func TestConfigValidate_PerActionAuthRejected(t *testing.T) {
	_, c := startTestDaemon(t)

	content := []byte("[security]\nper_action_auth = true\n")
	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: content}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected error for per_action_auth (unknown key), got none")
	}
	// The strict TOML parser says "strict mode: fields in the document are
	// missing in the target struct" — it does not embed the field name.
	// We just need at least one error whose message indicates an unknown-key
	// (strict mode) failure.
	found := false
	for _, e := range resp.Errors {
		if strings.Contains(e.Message, "strict mode") || strings.Contains(e.Message, "unknown") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors %v do not indicate a strict/unknown-key parse failure", resp.Errors)
	}
}

// TestConfigValidate_InvalidTOML: bad TOML → Errors non-empty, Parsed nil.
func TestConfigValidate_InvalidTOML(t *testing.T) {
	_, c := startTestDaemon(t)

	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: []byte("not toml [[[")}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected errors for invalid TOML")
	}
	if resp.Errors[0].Section != "toml" {
		t.Errorf("errors[0].section = %q, want \"toml\"", resp.Errors[0].Section)
	}
	if resp.Parsed != nil {
		t.Error("Parsed must be nil when errors are present")
	}
}

// TestConfigValidate_InvalidRange: out-of-range port → Errors non-empty, Parsed nil.
func TestConfigValidate_InvalidRange(t *testing.T) {
	_, c := startTestDaemon(t)

	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: []byte("[ui]\nport = 99999\n")}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Fatal("expected errors for out-of-range port")
	}
	if resp.Parsed != nil {
		t.Error("Parsed must be nil when errors are present")
	}
}

// TestConfigValidate_EmptyContent: empty content → Parsed populated with defaults.
func TestConfigValidate_EmptyContent(t *testing.T) {
	_, c := startTestDaemon(t)

	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: []byte{}}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}
	// Empty content is valid TOML (empty file = default config).
	if len(resp.Errors) != 0 {
		t.Fatalf("expected no errors for empty content; got: %v", resp.Errors)
	}
	if resp.Parsed == nil {
		t.Fatal("Parsed must be non-nil for empty content (defaults apply)")
	}
}

// TestConfigValidate_AuditEventEmitted: config.validate emits an audit event.
func TestConfigValidate_AuditEventEmitted(t *testing.T) {
	_, c := startTestDaemon(t)
	initUnlocked(t, c, []byte(authzPW))

	var resp ipc.ConfigValidateResp
	if err := c.Call(ipc.OpConfigValidate, ipc.ConfigValidateReq{Content: []byte("[ui]\nport = 2967\n")}, &resp); err != nil {
		t.Fatalf("config.validate: %v", err)
	}

	var auditResp ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 20}, &auditResp); err != nil {
		t.Fatalf("audit.tail: %v", err)
	}
	found := false
	for _, evt := range auditResp.Events {
		if evt.Op == string(ipc.OpConfigValidate) && evt.Outcome == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("config.validate audit event not found; events: %v", auditResp.Events)
	}
}
