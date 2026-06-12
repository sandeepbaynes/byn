package daemon

// execalias_test.go — NU-2.1 tests: alias expansion, pattern matching,
// defense-in-depth for bad record patterns, alias-vs-direct shadowing,
// ResolvedArgv contract.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// fetchAuditTail returns all audit events from the tail (up to 200).
func fetchAuditTail(t *testing.T, c *ipc.Client) ([]ipc.AuditEvent, error) {
	t.Helper()
	var tail ipc.AuditTailResp
	if err := c.Call(ipc.OpAuditTail, ipc.AuditTailReq{Lines: 200}, &tail); err != nil {
		return nil, err
	}
	return tail.Events, nil
}

// ── alias happy path ──────────────────────────────────────────────────────────

// TestAliasExecHappyPath: alias defined in the .byn, expansion matches a
// pattern action → free; ResolvedArgv returned; audit command is
// "alias <name> → <resolved>".
func TestAliasExecHappyPath(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok-val"))

	// Pattern allows "npm run start" with any extra args via {{args}}.
	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["npm run start {{args}}"]

[aliases]
test = "npm run start"
`)
	grantBynFile(t, c, byn, pw)

	// Alias "test" with no extra args: resolves to ["npm","run","start"].
	// Pattern "npm run start {{args}}" matches ({{args}} absorbs 0 tokens).
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias test",
		Alias:   "test",
		Argv:    nil, // no extra args
	})
	if err != nil {
		t.Fatalf("alias happy path: %v", err)
	}
	if len(resp.ResolvedArgv) == 0 {
		t.Fatal("ResolvedArgv must be non-empty on success")
	}
	want := []string{"npm", "run", "start"}
	if len(resp.ResolvedArgv) != len(want) {
		t.Fatalf("ResolvedArgv = %v, want %v", resp.ResolvedArgv, want)
	}
	for i, tok := range want {
		if resp.ResolvedArgv[i] != tok {
			t.Errorf("ResolvedArgv[%d] = %q, want %q", i, resp.ResolvedArgv[i], tok)
		}
	}

	// Values must flow.
	m := valueMap(resp.Values)
	if m["TOKEN"] != "tok-val" {
		t.Errorf("TOKEN = %q, want tok-val", m["TOKEN"])
	}

	// Audit command must show the alias resolution.
	// findExecAudit searches by command label; use the expected prefix.
	ev := findExecAudit(t, c, "alias test → npm run start")
	if ev == nil {
		t.Fatal("no exec audit event with alias label")
	}
	if ev.Outcome != "ok" {
		t.Errorf("outcome = %q, want ok", ev.Outcome)
	}
}

// TestAliasExecWithExtraArgs: alias + extra passthrough args; the resolved
// argv must include both the alias base and the extra args, and match a
// pattern with {{args}}.
func TestAliasExecWithExtraArgs(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["npm run test {{args}}"]

[aliases]
t = "npm run test"
`)
	grantBynFile(t, c, byn, pw)

	extraArgs := []string{"--watch", "--coverage"}
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias t",
		Alias:   "t",
		Argv:    extraArgs,
	})
	if err != nil {
		t.Fatalf("alias + extra args: %v", err)
	}

	want := []string{"npm", "run", "test", "--watch", "--coverage"}
	if len(resp.ResolvedArgv) != len(want) {
		t.Fatalf("ResolvedArgv = %v, want %v", resp.ResolvedArgv, want)
	}
	for i, tok := range want {
		if resp.ResolvedArgv[i] != tok {
			t.Errorf("ResolvedArgv[%d] = %q, want %q", i, resp.ResolvedArgv[i], tok)
		}
	}
	if m := valueMap(resp.Values); m["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected")
	}
}

// TestAliasExecExtraArgsStrictPattern: alias + extra args where the
// pattern does NOT include {{args}} → STRICT semantics → unmatched → auth_required.
func TestAliasExecExtraArgsStrictPattern(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// Pattern is "npm run build" (strict, no {{args}}); alias expands to same.
	// Adding extra args → resolved = ["npm","run","build","--prod"] → no match.
	byn := writeBynContent(t, `[scope]

[exec]
env = []
actions = ["npm run build"]

[aliases]
build = "npm run build"
`)
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias build",
		Alias:   "build",
		Argv:    []string{"--prod"}, // extra arg → resolved becomes ["npm","run","build","--prod"]
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("strict pattern + extra args: code = %v, want auth_required", code)
	}
}

// TestAliasExecValueFlows: alias exec injects the env vars from the .byn.
func TestAliasExecValueFlows(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "DB_URL", []byte("postgres://host/db"))
	putVar(t, c, ipc.Scope{}, "EXTRA", []byte("should-not-appear"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["DB_URL"]
actions = ["myapp run {{args}}"]

[aliases]
run = "myapp run"
`)
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Alias: "run",
		Argv:  []string{"--port", "3000"},
	})
	if err != nil {
		t.Fatalf("alias value flows: %v", err)
	}
	m := valueMap(resp.Values)
	if m["DB_URL"] != "postgres://host/db" {
		t.Errorf("DB_URL = %q, want postgres://host/db", m["DB_URL"])
	}
	if _, ok := m["EXTRA"]; ok {
		t.Error("EXTRA should not appear (not in env allowlist)")
	}
	// ResolvedArgv must be ["myapp","run","--port","3000"].
	wantArgv := []string{"myapp", "run", "--port", "3000"}
	if len(resp.ResolvedArgv) != len(wantArgv) {
		t.Fatalf("ResolvedArgv = %v, want %v", resp.ResolvedArgv, wantArgv)
	}
}

// ── missing alias → not_found with names hint ─────────────────────────────────

func TestAliasMissingNotFoundWithNames(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, `[scope]

[exec]
env = []
actions = []

[aliases]
start = "npm start"
build = "npm run build"
`)
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias no-such",
		Alias:   "no-such",
	})
	if code := errCode(t, err); code != ipc.CodeNotFound {
		t.Fatalf("missing alias: code = %v, want not_found", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if !strings.Contains(er.Message, "no-such") {
			t.Errorf("message = %q, want alias name mentioned", er.Message)
		}
		if !strings.Contains(er.Message, "[aliases]") {
			t.Errorf("message = %q, want '[aliases]' mentioned", er.Message)
		}
		// The hint should list available names.
		if !strings.Contains(er.Message, "start") || !strings.Contains(er.Message, "build") {
			t.Errorf("message = %q, want available alias names listed", er.Message)
		}
	}
}

func TestAliasMissingNoAliasesDefined(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	// No [aliases] table.
	byn := writeBynContent(t, "[scope]\n\n[exec]\nenv = []\nactions = []\n")
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias test",
		Alias:   "test",
	})
	if code := errCode(t, err); code != ipc.CodeNotFound {
		t.Fatalf("alias with no aliases: code = %v, want not_found", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if !strings.Contains(er.Message, "no aliases") {
			t.Errorf("message = %q, want 'no aliases' in message", er.Message)
		}
	}
}

// ── alias without .byn → bad_request ─────────────────────────────────────────

func TestAliasWithoutBynBadRequest(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		// No Path set — ad-hoc exec with alias is invalid.
		Path:    "",
		Command: "alias test",
		Alias:   "test",
	})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("alias without .byn: code = %v, want bad_request", code)
	}
	var er *ipc.ErrResponse
	if errors.As(err, &er) {
		if !strings.Contains(er.Message, "aliases require") {
			t.Errorf("message = %q, want 'aliases require' in message", er.Message)
		}
	}
}

// ── forged-record bad pattern → unmatched → auth required ────────────────────

// TestExecFetchBadPatternInRecord: a trust record with a syntactically-invalid
// action pattern (simulating a hand-MAC'd record that bypasses grant-time
// validation) is treated as NON-matching → auth_required (fail-closed, no
// panic, no widening).
func TestExecFetchBadPatternInRecord(t *testing.T) {
	d, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("s3cret"))

	// Write and grant a valid .byn first to get a proper trust record.
	const validBody = "[scope]\n\n[exec]\nenv = [\"SECRET\"]\nactions = [\"good-cmd\"]\n"
	byn := writeBynContent(t, validBody)

	canon := trust.Canonicalize(byn)
	hash := trust.Hash([]byte(validBody))

	// Derive the vk-MAC key directly.
	entry, err := d.openVault(context.Background(), "default")
	if err != nil {
		t.Fatalf("openVault: %v", err)
	}
	vkKey, err := entry.store.DeriveSubkey(trust.VKMACKeyInfo)
	if err != nil {
		t.Fatalf("DeriveSubkey: %v", err)
	}

	fi, serr := os.Stat(byn)
	if serr != nil {
		t.Fatalf("stat: %v", serr)
	}

	// Hand-write a record with an invalid (unparseable) action pattern.
	// "{{badtype}}" will fail ParseActionPattern (unknown placeholder type).
	rec := trust.Record{
		Path:          canon,
		SHA256:        hash,
		Vault:         "default",
		MTimeUnixNano: fi.ModTime().UnixNano(),
		Snapshot:      validBody,
		Actions:       []string{"{{badtype}}"}, // invalid pattern — defense in depth
	}
	rec.SetMACs(d.fpMACKey, vkKey)
	if _, perr := trust.Put(d.cfg.Dir, rec); perr != nil {
		t.Fatalf("Put forged record: %v", perr)
	}

	// Execute with Argv that would have matched if the pattern were "good-cmd".
	// The bad pattern must be skipped (non-matching), and with no valid
	// match, auth_required should fire.
	_, execErr := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "good-cmd",
		Argv:    []string{"good-cmd"},
	})
	if code := errCode(t, execErr); code != ipc.CodeAuthRequired {
		t.Fatalf("bad pattern in record: code = %v, want auth_required (defense in depth)", code)
	}
	// With password it must succeed (bad pattern is skipped, not fatal).
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:     byn,
		Command:  "good-cmd",
		Argv:     []string{"good-cmd"},
		Password: pw,
	})
	if err != nil {
		t.Fatalf("bad pattern in record + password: want ok, got: %v", err)
	}
	if valueMap(resp.Values)["SECRET"] != "s3cret" {
		t.Errorf("SECRET not injected after authorized exec with bad pattern in record")
	}
}

// ── pattern matching (not exact string) ──────────────────────────────────────

// TestPatternMatchUUID: action pinned with {{uuid}} placeholder matches
// a valid UUID at runtime; non-UUID fails.
func TestPatternMatchUUID(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["deploy --id {{uuid}}"]
`)
	grantBynFile(t, c, byn, pw)

	validUUID := "550e8400-e29b-41d4-a716-446655440000"

	// Valid UUID → match → free.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"deploy", "--id", validUUID},
	})
	if err != nil {
		t.Fatalf("UUID pattern match: %v", err)
	}
	if m := valueMap(resp.Values); m["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected")
	}

	// Non-UUID → no match → auth_required.
	_, err = execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"deploy", "--id", "not-a-uuid"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("non-UUID pattern: code = %v, want auth_required", code)
	}
}

// TestPatternMatchArgsTail: action pinned with {{args}} absorbs extra tokens.
func TestPatternMatchArgsTail(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["git commit {{args}}"]
`)
	grantBynFile(t, c, byn, pw)

	// Many extra args absorbed by {{args}}.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"git", "commit", "-m", "msg", "--no-edit"},
	})
	if err != nil {
		t.Fatalf("args tail pattern: %v", err)
	}
	if m := valueMap(resp.Values); m["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected")
	}

	// Base command without extra args also matches ({{args}} absorbs 0).
	resp2, err2 := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"git", "commit"},
	})
	if err2 != nil {
		t.Fatalf("args tail zero extra: %v", err2)
	}
	if m := valueMap(resp2.Values); m["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected (zero extra args case)")
	}
}

// TestPatternMatchWrongBaseCommand: matched command with {{args}} does NOT
// match a different base command — strict literal prefix.
func TestPatternMatchWrongBaseCommand(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, `[scope]

[exec]
env = []
actions = ["git commit {{args}}"]
`)
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"git", "push"},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("wrong base: code = %v, want auth_required", code)
	}
}

// ── ResolvedArgv for direct exec ──────────────────────────────────────────────

// TestDirectExecResolvedArgvReturned: direct exec (no alias) must return
// ResolvedArgv in the response so the CLI has a single authoritative contract.
func TestDirectExecResolvedArgvReturned(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, `[scope]

[exec]
env = []
actions = ["myapp run"]
`)
	grantBynFile(t, c, byn, pw)

	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path: byn,
		Argv: []string{"myapp", "run"},
	})
	if err != nil {
		t.Fatalf("direct exec ResolvedArgv: %v", err)
	}
	if len(resp.ResolvedArgv) == 0 {
		t.Fatal("ResolvedArgv must be non-empty for direct exec")
	}
	if resp.ResolvedArgv[0] != "myapp" || resp.ResolvedArgv[1] != "run" {
		t.Errorf("ResolvedArgv = %v, want [myapp run]", resp.ResolvedArgv)
	}
}

// ── alias audit label ─────────────────────────────────────────────────────────

// TestAliasAuditCommandLabel: alias exec audit event shows
// "alias <name> → <resolved>" in the Command field.
func TestAliasAuditCommandLabel(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["npm test {{args}}"]

[aliases]
test = "npm test"
`)
	grantBynFile(t, c, byn, pw)

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias test",
		Alias:   "test",
		Argv:    []string{"--watch"},
	})
	if err != nil {
		t.Fatalf("alias audit label: %v", err)
	}

	// Audit event's command must contain the alias resolution.
	ev := findExecAudit(t, c, "alias test → npm test --watch")
	if ev == nil {
		t.Fatal("no exec audit event for alias exec with --watch")
	}
	if ev.Outcome != "ok" {
		t.Errorf("outcome = %q, want ok", ev.Outcome)
	}
}

// ── alias + actions "*" wildcard combination ──────────────────────────────────

// TestAliasWithActionsWildcard: when [exec] actions = "*" and the request uses
// alias form, the exec runs free AND ActionsWildcard is set in the response.
// This covers the intersection of alias expansion + wildcard gate.
func TestAliasWithActionsWildcard(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "SECRET", []byte("sec-val"))

	byn := writeBynContent(t, `[scope]

[exec]
env = ["SECRET"]
actions = "*"

[aliases]
run = "myapp start"
`)
	grantBynFile(t, c, byn, pw)

	// Alias exec with wildcard: must run free, must set ActionsWildcard, must
	// return ResolvedArgv = ["myapp", "start"].
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:    byn,
		Command: "alias run",
		Alias:   "run",
		Argv:    nil,
	})
	if err != nil {
		t.Fatalf("alias + wildcard: want free, got: %v", err)
	}
	if !resp.ActionsWildcard {
		t.Error("ActionsWildcard must be true for actions = \"*\"")
	}
	wantArgv := []string{"myapp", "start"}
	if len(resp.ResolvedArgv) != len(wantArgv) {
		t.Fatalf("ResolvedArgv = %v, want %v", resp.ResolvedArgv, wantArgv)
	}
	for i, tok := range wantArgv {
		if resp.ResolvedArgv[i] != tok {
			t.Errorf("ResolvedArgv[%d] = %q, want %q", i, resp.ResolvedArgv[i], tok)
		}
	}
	m := valueMap(resp.Values)
	if m["SECRET"] != "sec-val" {
		t.Errorf("SECRET = %q, want sec-val", m["SECRET"])
	}
}

// ── 200-cap audit label truncation ───────────────────────────────────────────

// TestAliasAuditLabelTruncatedAt200: when the resolved alias label is longer
// than 200 characters, the audit command is capped at 200 chars + "…".
func TestAliasAuditLabelTruncatedAt200(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)

	byn := writeBynContent(t, `[scope]

[exec]
env = []
actions = ["longcmd {{args}}"]

[aliases]
longcmd = "longcmd"
`)
	grantBynFile(t, c, byn, pw)

	// Build an argv of extra args that when combined with the alias label
	// "alias longcmd → longcmd <args...>" exceeds 200 characters.
	// "alias longcmd → longcmd " is 24 chars; we need 200 - 24 + some = >176 chars.
	// Each arg is "arg" (3 chars) + space (1) = 4; 50 args = 200 chars of args
	// so total label will be ~224 chars → gets capped.
	extraArgs := make([]string, 50)
	for i := range extraArgs {
		extraArgs[i] = "arg"
	}

	_, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Alias: "longcmd",
		Argv:  extraArgs,
	})
	if err != nil {
		t.Fatalf("long audit label: %v", err)
	}

	// The audit event's Command field must be at most 200+1 chars (the "…" is
	// a multibyte rune so the string ends with "…" after ≤200 ASCII chars).
	// findExecAudit searches by prefix; use "alias longcmd →" as the prefix.
	evs, tailErr := fetchAuditTail(t, c)
	if tailErr != nil {
		t.Fatalf("audit tail: %v", tailErr)
	}
	var found string
	for _, ev := range evs {
		if strings.HasPrefix(ev.Command, "alias longcmd →") {
			found = ev.Command
			break
		}
	}
	if found == "" {
		t.Fatal("no exec audit event with 'alias longcmd →' prefix")
	}
	// The raw string length must be ≤ 200 + len("…") = 200 + 3 bytes (UTF-8 ellipsis).
	// The cap leaves 200 ASCII chars then appends "…" (3 bytes) = 203 bytes max.
	const maxBytes = 203
	if len(found) > maxBytes {
		t.Errorf("audit command length = %d bytes, want ≤ %d (200 ASCII + '…')", len(found), maxBytes)
	}
	if !strings.HasSuffix(found, "…") {
		t.Errorf("audit command = %q, want suffix '…' (truncation marker)", found)
	}
}

// ── URL-host pattern through alias exec ──────────────────────────────────────

// TestAliasURLHostPatternEvil: alias + {{url:host=...}} pattern — a matching
// host passes, but providing an evil host as an extra arg causes a mismatch
// and triggers auth_required.
//
// This tests the full daemon-side path: alias expansion → resolvedArgv →
// ParseActionPattern → Match with URL constraint → denied for wrong host.
func TestAliasURLHostPatternEvil(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte(authzPW)
	initUnlocked(t, c, pw)
	putVar(t, c, ipc.Scope{}, "TOKEN", []byte("tok"))

	// Pattern: scraper-style alias.  The action allows the base command with
	// exactly one {{url:host=www.website.com}} argument (via the alias
	// expanding and the URL being the extra arg).
	byn := writeBynContent(t, `[scope]

[exec]
env = ["TOKEN"]
actions = ["scrape {{url:host=www.website.com}}"]

[aliases]
scrape = "scrape"
`)
	grantBynFile(t, c, byn, pw)

	validURL := "https://www.website.com/page"
	evilURL := "https://www.evil.com/page"

	// Valid host: alias "scrape" + extra arg validURL → resolved ["scrape", validURL]
	// → matches pattern "scrape {{url:host=www.website.com}}" → free.
	resp, err := execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Alias: "scrape",
		Argv:  []string{validURL},
	})
	if err != nil {
		t.Fatalf("valid URL host: want free, got: %v", err)
	}
	if m := valueMap(resp.Values); m["TOKEN"] != "tok" {
		t.Errorf("TOKEN not injected for valid URL host")
	}

	// Evil host: alias "scrape" + extra arg evilURL → resolved ["scrape", evilURL]
	// → does NOT match (host mismatch) → auth_required.
	_, err = execFetch(t, c, ipc.ExecFetchReq{
		Path:  byn,
		Alias: "scrape",
		Argv:  []string{evilURL},
	})
	if code := errCode(t, err); code != ipc.CodeAuthRequired {
		t.Fatalf("evil URL host: code = %v, want auth_required", code)
	}
}
