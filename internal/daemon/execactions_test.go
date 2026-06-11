package daemon

// Tests for NU-2: [exec] actions enforcement.
//
// Gate matrix:
//   policy "always"  → auth required even for matched/wildcard
//   policy "none"    → any command runs free (wildcard-equivalent)
//   default/trusted:
//     actions wildcard ("*") → free + ActionsWildcard flag
//     matched (exact argv)   → free
//     unmatched / empty      → auth_required
//
// Independence: actions enforcement is INDEPENDENT of the global
// per_action_auth flag. The flag governs ops WITHOUT a .byn contract;
// the .byn [exec] actions list governs exec WITH a .byn contract.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// grantBynWithActions writes and grants a .byn with [exec] env allowlist and
// an [exec] actions list. actionsToml should be a TOML value like
// `["cmd arg"]` or `"*"` or `[]`.
func grantBynWithActions(t *testing.T, c *ipc.Client, envVars []string, actionsToml string, pw []byte) string {
	t.Helper()
	envToml := "[]"
	if len(envVars) > 0 {
		parts := make([]string, len(envVars))
		for i, v := range envVars {
			parts[i] = `"` + v + `"`
		}
		envToml = "[" + strings.Join(parts, ", ") + "]"
	}
	content := "[scope]\n\n[exec]\nenv = " + envToml + "\nactions = " + actionsToml + "\n"
	byn := writeBynContent(t, content)
	grantBynFile(t, c, byn, pw)
	return byn
}

// grantBynWithActionsAndAuth writes and grants a .byn with [exec] env, actions, and [auth] exec.
func grantBynWithActionsAndAuth(t *testing.T, c *ipc.Client, envVars []string, actionsToml string, execAuth string, pw []byte) string {
	t.Helper()
	envToml := "[]"
	if len(envVars) > 0 {
		parts := make([]string, len(envVars))
		for i, v := range envVars {
			parts[i] = `"` + v + `"`
		}
		envToml = "[" + strings.Join(parts, ", ") + "]"
	}
	content := "[scope]\n\n[exec]\nenv = " + envToml + "\nactions = " + actionsToml + "\n\n[auth]\nexec = \"" + execAuth + "\"\n"
	byn := writeBynContent(t, content)
	grantBynFile(t, c, byn, pw)
	return byn
}

// ── matched action runs free ─────────────────────────────────────────────────

// TestActionsMatchedRunsFree: an argv that exactly matches a pinned action
// runs without credentials.
func TestActionsMatchedRunsFree(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok-val"))

	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `["aws s3 ls"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "aws s3 ls",
		Argv:    []string{"aws", "s3", "ls"},
	})
	if err != nil {
		t.Fatalf("matched action: want free, got error: %v", err)
	}
	m := valueMap(resp.Values)
	if m["TOKEN"] != "tok-val" {
		t.Errorf("TOKEN = %q, want tok-val", m["TOKEN"])
	}
	if resp.ActionsWildcard {
		t.Error("ActionsWildcard should be false for an explicit pinned list")
	}
}

// TestActionsMatchedRunsFreeWithFlagOn: pinned action runs free even when
// per_action_auth is on — the flag is INDEPENDENT of the .byn contract.
func TestActionsMatchedRunsFreeWithFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("secret-val"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["myapp --run"]`, pw)

	// No password — pinned action must run free regardless of global flag.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "myapp --run",
		Argv:    []string{"myapp", "--run"},
	})
	if err != nil {
		t.Fatalf("matched action (flag on): want free, got error: %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "secret-val" {
		t.Errorf("SECRET = %q, want secret-val", m["SECRET"])
	}
}

// ── unmatched command requires auth ──────────────────────────────────────────

// TestActionsUnmatchedNoCreds: unmatched command + no creds → auth_required
// with the "not pinned" message; audited.
func TestActionsUnmatchedNoCreds(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "other-cmd",
		Argv:    []string{"other-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("unmatched cmd: code = %v, want auth_required", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if !strings.Contains(er.Message, "not pinned") {
			t.Errorf("message = %q, want 'not pinned' in it", er.Message)
		}
		if !strings.Contains(er.Recover, "[exec] actions") {
			t.Errorf("recover = %q, want '[exec] actions' mentioned", er.Recover)
		}
	}

	// Must be audited as denied.
	ev := findExecAudit(t, c, "other-cmd")
	if ev == nil {
		t.Fatal("no exec audit event for unmatched actions denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.ErrorCode != string(ipc.CodeAuthRequired) {
		t.Errorf("error_code = %q, want auth_required", ev.ErrorCode)
	}
}

// TestActionsUnmatchedWithPassword: unmatched command + correct password →
// injection succeeds (only allowlisted env vars flow).
func TestActionsUnmatchedWithPassword(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))
	putVar(t, c, ipc.Scope{}, "EXTRA", []byte("extra"))

	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `["pinned-cmd"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other-cmd",
		Argv:     []string{"other-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("unmatched cmd + password: want ok, got: %v", err)
	}
	// Only TOKEN (in the env allowlist) flows; EXTRA doesn't.
	m := valueMap(resp.Values)
	if m["TOKEN"] != "tok" {
		t.Errorf("TOKEN = %q, want tok", m["TOKEN"])
	}
	if _, ok := m["EXTRA"]; ok {
		t.Error("EXTRA should not appear (not in env allowlist)")
	}
}

// ── empty actions → every command needs auth ─────────────────────────────────

// TestActionsEmptyEveryCommandNeedsAuth: empty [exec] actions list → every
// exec needs per-action auth (the secure default — no command runs free).
func TestActionsEmptyEveryCommandNeedsAuth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `[]`, pw)

	// No Argv, no password: must require auth.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "any-cmd",
		Argv:    []string{"any-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("empty actions no creds: code = %v, want auth_required", code)
	}

	// With password: succeeds.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "any-cmd",
		Argv:     []string{"any-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("empty actions + password: want ok, got: %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "s3cret" {
		t.Errorf("SECRET = %q, want s3cret", m["SECRET"])
	}
}

// TestActionsAbsentEveryCommandNeedsAuth: .byn with no [exec] actions at all
// (i.e., record.Actions is nil) → every exec needs auth (secure default).
func TestActionsAbsentEveryCommandNeedsAuth(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Write a .byn with no [exec] section at all.
	byn := writeBynContent(t, "[scope]\n")
	grantBynFile(t, c, byn, pw)

	// No password: must require auth.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "any-cmd",
		Argv:    []string{"any-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("absent actions no creds: code = %v, want auth_required", code)
	}

	// With password: succeeds.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "any-cmd",
		Argv:     []string{"any-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("absent actions + password: want ok, got: %v", err)
	}
	// No env allowlist → no vars injected.
	if len(resp.Values) != 0 {
		t.Errorf("Values = %v, want empty (no env allowlist)", resp.Values)
	}
}

// ── actions wildcard → all commands free + flag set ──────────────────────────

// TestActionsWildcardAllFree: actions = "*" → any command runs free, no
// password needed; ActionsWildcard flag is set in the response.
func TestActionsWildcardAllFree(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `"*"`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "arbitrary-cmd --flag",
		Argv:    []string{"arbitrary-cmd", "--flag"},
	})
	if err != nil {
		t.Fatalf("actions wildcard: want free, got error: %v", err)
	}
	if !resp.ActionsWildcard {
		t.Error("ActionsWildcard should be true for actions = \"*\"")
	}
	m := valueMap(resp.Values)
	if m["TOKEN"] != "tok" {
		t.Errorf("TOKEN = %q, want tok", m["TOKEN"])
	}
}

// TestActionsWildcardListForm: actions = ["*"] (list form) works the same as
// the bare string.
func TestActionsWildcardListForm(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `["*"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "some-cmd",
		Argv:    []string{"some-cmd"},
	})
	if err != nil {
		t.Fatalf("actions [\"*\"] list form: want free, got error: %v", err)
	}
	if !resp.ActionsWildcard {
		t.Error("ActionsWildcard should be true for actions = [\"*\"]")
	}
}

// ── [auth] exec = "always" gates even matched actions ───────────────────────

// TestAuthExecAlwaysGatesMatchedAction: [auth] exec = "always" means even a
// pinned/matched command requires fresh auth.
func TestAuthExecAlwaysGatesMatchedAction(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActionsAndAuth(t, c, []string{"SECRET"}, `["matched-cmd"]`, "always", pw)

	// No creds → auth_required even though the command is pinned.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "matched-cmd",
		Argv:    []string{"matched-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("auth=always matched: code = %v, want auth_required", code)
	}

	// With password → succeeds.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "matched-cmd",
		Argv:     []string{"matched-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("auth=always matched + password: %v", err)
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "s3cret" {
		t.Errorf("SECRET = %q, want s3cret", m["SECRET"])
	}
}

// TestAuthExecAlwaysGatesWildcard: [auth] exec = "always" gates even the
// wildcard case (no command runs free).
func TestAuthExecAlwaysGatesWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActionsAndAuth(t, c, []string{"SECRET"}, `"*"`, "always", pw)

	// No creds → auth_required even though actions = "*".
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "any-cmd",
		Argv:    []string{"any-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("auth=always wildcard: code = %v, want auth_required", code)
	}

	// With password → succeeds.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "any-cmd",
		Argv:     []string{"any-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("auth=always wildcard + password: %v", err)
	}
	if len(resp.Values) == 0 {
		t.Error("expected values injected after authorized exec")
	}
}

// ── [auth] exec = "none" frees all commands ──────────────────────────────────

// TestAuthExecNoneFreesAll: [auth] exec = "none" → any command runs free,
// even if it's not in the actions list (none≡wildcard-equivalent behavior).
// The loud warning was shown at grant time (Task 3).
func TestAuthExecNoneFreesAll(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	// Empty actions + exec = "none": the "none" policy overrides the empty list.
	byn := grantBynWithActionsAndAuth(t, c, []string{"TOKEN"}, `[]`, "none", pw)

	// No creds → still succeeds because exec = "none".
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "any-unlisted-cmd",
		Argv:    []string{"any-unlisted-cmd"},
	})
	if err != nil {
		t.Fatalf("auth=none: want free, got error: %v", err)
	}
	m := valueMap(resp.Values)
	if m["TOKEN"] != "tok" {
		t.Errorf("TOKEN = %q, want tok", m["TOKEN"])
	}
}

// ── exact-match edge cases ───────────────────────────────────────────────────

// TestActionsExtraFlagNoMatch: an argv with an extra flag does NOT match a
// pinned action without that flag (exact match semantics).
func TestActionsExtraFlagNoMatch(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Pin "aws s3 ls" but not "aws s3 ls --human".
	byn := grantBynWithActions(t, c, []string{}, `["aws s3 ls"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "aws s3 ls --human",
		Argv:    []string{"aws", "s3", "ls", "--human"},
	})
	// Must require auth (extra flag → no match).
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("extra flag: code = %v, want auth_required", code)
	}
}

// TestActionsSubsetNoMatch: a subset of the pinned action's argv does NOT match.
func TestActionsSubsetNoMatch(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Pin "aws s3 ls --bucket foo" but not "aws s3 ls".
	byn := grantBynWithActions(t, c, []string{}, `["aws s3 ls --bucket foo"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "aws s3 ls",
		Argv:    []string{"aws", "s3", "ls"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("subset argv: code = %v, want auth_required", code)
	}
}

// TestActionsEmptyArgvFailsClosed: empty Argv (old CLI / version skew) is
// treated as unmatched → auth required (fail-closed).
func TestActionsEmptyArgvFailsClosed(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Even with a wildcard env, empty Argv means unmatched → auth.
	byn := grantBynWithActions(t, c, []string{}, `["some-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "some-cmd",
		// Argv intentionally absent (nil) — simulates old CLI.
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("empty Argv: code = %v, want auth_required (fail-closed)", code)
	}
}

// ── independence from per_action_auth flag ───────────────────────────────────

// TestActionsIndependentOfPerActionAuthFlag: the actions gate applies
// regardless of the global per_action_auth flag — a pinned command is free
// even with the flag on; an unmatched command requires auth even with the
// flag off.
func TestActionsIndependentOfPerActionAuthFlag(t *testing.T) {
	t.Run("flagOn/matched=free", func(t *testing.T) {
		_, c := startPerActionDaemonWithClient(t)
		pw := []byte(authzPW)
		initUnlocked(t, c, pw)
		putVar(t, c, ipc.Scope{}, "K", []byte("v"))

		byn := grantBynWithActions(t, c, []string{"K"}, `["deploy.sh"]`, pw)
		resp, err := execFetch(t, c, ipc.ExecFetchReq{
			Path:    byn,
			Command: "deploy.sh",
			Argv:    []string{"deploy.sh"},
		})
		if err != nil {
			t.Fatalf("flag on + matched: want free, got: %v", err)
		}
		if valueMap(resp.Values)["K"] != "v" {
			t.Errorf("K not injected")
		}
	})

	t.Run("flagOff/unmatched=auth", func(t *testing.T) {
		// startTestDaemon has per_action_auth = false.
		_, c := startTestDaemon(t)
		pw := []byte(authzPW)
		initUnlocked(t, c, pw)
		putVar(t, c, ipc.Scope{}, "K", []byte("v"))

		byn := grantBynWithActions(t, c, []string{"K"}, `["deploy.sh"]`, pw)
		_, err := execFetch(t, c, ipc.ExecFetchReq{
			Path:    byn,
			Command: "other-cmd",
			Argv:    []string{"other-cmd"},
		})
		if code := errCode(t, err); code != ipc.CodeAuthRequired {
			t.Fatalf("flag off + unmatched: code = %v, want auth_required", code)
		}
	})
}

// ── audit rows ───────────────────────────────────────────────────────────────

// TestActionsUnmatchedAuditedAsAuthRequired: an unmatched-action denial
// produces an audit row with outcome=denied and error_code=auth_required.
func TestActionsUnmatchedAuditedAsAuthRequired(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := grantBynWithActions(t, c, []string{}, `["pinned"]`, pw)
	canon := trust.Canonicalize(byn)

	const cmd = "unlisted-cmd"
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: cmd,
		Argv:    []string{"unlisted-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("code = %v, want auth_required", code)
	}

	ev := findExecAudit(t, c, cmd)
	if ev == nil {
		t.Fatal("no exec audit event for unmatched action denial")
	}
	if ev.Outcome != "denied" {
		t.Errorf("outcome = %q, want denied", ev.Outcome)
	}
	if ev.ErrorCode != string(ipc.CodeAuthRequired) {
		t.Errorf("error_code = %q, want auth_required", ev.ErrorCode)
	}
	if ev.BynPath != canon {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, canon)
	}
}

// ── CRITICAL: unconditional credential verification (Finding 1) ─────────────
//
// The [exec] actions gate MUST verify credentials UNCONDITIONALLY — independent
// of the global [security] per_action_auth flag.  All four of these tests are
// run TWICE: once with the flag OFF (default) and once with it ON to pin that
// the behavior is identical in both cases.

// TestActionsUnmatchedWrongPasswordFlagOff: flag=OFF, unmatched command,
// wrong password → CodeWrongPassword; rate-limiter failure is recorded.
func TestActionsUnmatchedWrongPasswordFlagOff(t *testing.T) {
	// startTestDaemon has per_action_auth = false.
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other-cmd",
		Argv:     []string{"other-cmd"},
		Password: []byte("wrong-password"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("flagOFF + unmatched + wrong pw: code = %v, want wrong_password (flag off must not short-circuit)", code)
	}
}

// TestActionsUnmatchedWrongPasswordFlagOn: flag=ON, unmatched command,
// wrong password → CodeWrongPassword (identical to flag=OFF).
func TestActionsUnmatchedWrongPasswordFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other-cmd",
		Argv:     []string{"other-cmd"},
		Password: []byte("wrong-password"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("flagON + unmatched + wrong pw: code = %v, want wrong_password", code)
	}
}

// TestActionsUnmatchedNoCredsFlagOff: flag=OFF, unmatched command, no creds
// → CodeAuthRequired with "[exec] actions" in the recover hint.
func TestActionsUnmatchedNoCredsFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "other-cmd",
		Argv:    []string{"other-cmd"},
		// No password or presence token.
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("flagOFF + unmatched + no creds: code = %v, want auth_required", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if !strings.Contains(er.Recover, "[exec] actions") {
			t.Errorf("recover = %q, want '[exec] actions' mentioned", er.Recover)
		}
	}
}

// TestActionsUnmatchedNoCredsFlagOn: flag=ON, unmatched command, no creds
// → CodeAuthRequired (identical to flag=OFF — independence).
func TestActionsUnmatchedNoCredsFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "other-cmd",
		Argv:    []string{"other-cmd"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("flagON + unmatched + no creds: code = %v, want auth_required", code)
	}
}

// TestActionsUnmatchedCorrectPasswordFlagOff: flag=OFF, unmatched command,
// correct password → values flow through.
func TestActionsUnmatchedCorrectPasswordFlagOff(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other-cmd",
		Argv:     []string{"other-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("flagOFF + unmatched + correct pw: want ok, got: %v", err)
	}
	if valueMap(resp.Values)["SECRET"] != "s3cret" {
		t.Errorf("SECRET not injected after authorized unmatched exec")
	}
}

// TestActionsUnmatchedCorrectPasswordFlagOn: flag=ON, unmatched command,
// correct password → values flow (identical to flag=OFF — independence).
func TestActionsUnmatchedCorrectPasswordFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned-cmd"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other-cmd",
		Argv:     []string{"other-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("flagON + unmatched + correct pw: want ok, got: %v", err)
	}
	if valueMap(resp.Values)["SECRET"] != "s3cret" {
		t.Errorf("SECRET not injected after authorized unmatched exec (flag on)")
	}
}

// TestAuthExecAlwaysWrongPasswordFlagOff: [auth] exec="always", flag=OFF,
// wrong password → CodeWrongPassword (MUST NOT skip due to flag=OFF).
func TestAuthExecAlwaysWrongPasswordFlagOff(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActionsAndAuth(t, c, []string{"SECRET"}, `["matched-cmd"]`, "always", pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "matched-cmd",
		Argv:     []string{"matched-cmd"},
		Password: []byte("wrong-pw"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("exec=always flagOFF wrong pw: code = %v, want wrong_password", code)
	}
}

// TestAuthExecAlwaysWrongPasswordFlagOn: [auth] exec="always", flag=ON,
// wrong password → CodeWrongPassword (identical to flag=OFF).
func TestAuthExecAlwaysWrongPasswordFlagOn(t *testing.T) {
	_, c := startPerActionDaemonWithClient(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActionsAndAuth(t, c, []string{"SECRET"}, `["matched-cmd"]`, "always", pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "matched-cmd",
		Argv:     []string{"matched-cmd"},
		Password: []byte("wrong-pw"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("exec=always flagON wrong pw: code = %v, want wrong_password", code)
	}
}

// TestActionsUnmatchedRateLimiterRecorded: wrong password on unmatched command
// increments the rate-limiter; a second immediate wrong-password attempt hits
// backoff (rate_limited). This pins that the rate-limiter is active on the
// unconditional credential path.
func TestActionsUnmatchedRateLimiterRecorded(t *testing.T) {
	_, c := startTestDaemon(t) // flag OFF — unconditional path must still rate-limit
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := grantBynWithActions(t, c, []string{}, `["pinned"]`, pw)

	// First wrong password → wrong_password.
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other",
		Argv:     []string{"other"},
		Password: []byte("bad-pw"),
	})
	if code := errCode(t, err); code != ipc.CodeWrongPassword {
		t.Fatalf("first wrong pw: code = %v, want wrong_password", code)
	}

	// Second wrong password immediately → rate_limited.
	_, err2 := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other",
		Argv:     []string{"other"},
		Password: []byte("bad-pw2"),
	})
	if code := errCode(t, err2); code != ipc.CodeRateLimited {
		t.Fatalf("second wrong pw: code = %v, want rate_limited", code)
	}
	// Recover hint must include a duration.
	var rl *ipc.ErrResponse
	if errors.As(err2, &rl) {
		if !strings.Contains(rl.Recover, "retry after") {
			t.Errorf("rate-limited recover = %q, want 'retry after ...'", rl.Recover)
		}
	}
}

// ── Finding 4: token-wise argv matching ──────────────────────────────────────

// TestActionsTokenWiseMatchSpaceInArg: an argv where one token contains a
// literal space (["pnpm","run start"]) must NOT match the pinned action
// "pnpm run start" (whose token expansion is ["pnpm","run","start"]).
// This pins that matching is token-wise, not join-based.
func TestActionsTokenWiseMatchSpaceInArg(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Pin "pnpm run start" (token-wise: ["pnpm","run","start"]).
	byn := grantBynWithActions(t, c, []string{}, `["pnpm run start"]`, pw)

	// Argv has a token with a literal space: ["pnpm", "run start"].
	// This must NOT match (different token count; different tokens).
	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "pnpm run start",
		Argv:    []string{"pnpm", "run start"}, // "run start" is ONE token with a space
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("space-in-arg: code = %v, want auth_required (token-wise mismatch)", code)
	}
}

// TestActionsTokenWiseMatchCorrect: the same action IS matched when Argv has
// the correct token breakdown (["pnpm","run","start"]).
func TestActionsTokenWiseMatchCorrect(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `["pnpm run start"]`, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "pnpm run start",
		Argv:    []string{"pnpm", "run", "start"}, // correct token expansion
	})
	if err != nil {
		t.Fatalf("correct token expansion: want free, got: %v", err)
	}
	if valueMap(resp.Values)["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected for correctly matched action")
	}
}

// ── delay between rate-limit tests ───────────────────────────────────────────
// After TestActionsUnmatchedRateLimiterRecorded we need the limiter to reset.
// Each sub-test uses its own daemon instance so rate-limiter state is isolated.

// TestActionsUnmatchedAfterRateLimitResets: after waiting for the back-off
// to expire, a correct password succeeds on the same .byn.
// This test uses a fresh daemon to avoid inter-test limiter pollution.
func TestActionsUnmatchedAfterRateLimitResets(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	byn := grantBynWithActions(t, c, []string{"SECRET"}, `["pinned"]`, pw)

	// First bad password triggers the limiter.
	_, _ = execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Argv:     []string{"other"},
		Password: []byte("bad"),
	})
	// Wait for back-off (default base is 500ms).
	time.Sleep(600 * time.Millisecond)

	// Correct password after reset → succeeds.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "other",
		Argv:     []string{"other"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("after rate-limit reset: %v", err)
	}
	if valueMap(resp.Values)["SECRET"] != "s3cret" {
		t.Errorf("SECRET not injected after reset + correct pw")
	}
}

// TestActionsMatchedAuditedAsOk: a matched-action exec produces an audit
// row with outcome=ok.
func TestActionsMatchedAuditedAsOk(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	const pinnedCmd = "kubectl apply -f deploy.yaml"
	byn := grantBynWithActions(t, c, []string{"TOKEN"}, `["kubectl apply -f deploy.yaml"]`, pw)
	canon := trust.Canonicalize(byn)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: pinnedCmd,
		Argv:    []string{"kubectl", "apply", "-f", "deploy.yaml"},
	})
	if err != nil {
		t.Fatalf("matched action: %v", err)
	}

	ev := findExecAudit(t, c, pinnedCmd)
	if ev == nil {
		t.Fatal("no exec audit event for matched action")
	}
	if ev.Outcome != "ok" {
		t.Errorf("outcome = %q, want ok", ev.Outcome)
	}
	if ev.BynPath != canon {
		t.Errorf("byn_path = %q, want %q", ev.BynPath, canon)
	}
}
