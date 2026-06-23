package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestRunAudit_NoSubcommand(t *testing.T) {
	if got := runAudit(nil, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAudit_Help(t *testing.T) {
	for _, h := range []string{"help", "--help", "-h"} {
		if got := runAudit([]string{h}, cliScope{}); got != exitOK {
			t.Fatalf("%q got %d", h, got)
		}
	}
}

func TestRunAudit_Unknown(t *testing.T) {
	if got := runAudit([]string{"explode"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditTail_Empty(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{})
	if got := runAudit([]string{"tail"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditTail_WithEvents(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{
		Events: []ipc.AuditEvent{{
			TS:        time.Now().UnixNano(),
			Op:        "put",
			Project:   "p",
			Env:       "e",
			EntryName: "K",
			Outcome:   "ok",
		}, {
			TS:      time.Now().UnixNano(),
			Op:      "lock",
			Outcome: "ok",
		}},
	})
	if got := runAudit([]string{"tail"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

// A snapshot `tail --json` (no -f) must emit a single JSON array — the same
// shape as `audit view --json` and every other --json command — not NDJSON.
func TestRunAuditTail_JSON(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{Events: []ipc.AuditEvent{
		{Op: "put", Outcome: "ok"}, {Op: "lock", Outcome: "ok"},
	}})
	var code int
	out := captureStdout(t, func() { code = runAudit([]string{"tail", "--json"}, cliScope{}) })
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var events []map[string]any
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("tail --json must be one JSON array, got:\n%s\nerr=%v", out, err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
}

func TestRunAuditTail_BadFlag(t *testing.T) {
	if got := runAudit([]string{"tail", "--nope"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditTail_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runAudit([]string{"tail"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditTail_LinesFlag(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{})
	_ = runAudit([]string{"tail", "--lines=5"}, cliScope{})
	var req ipc.AuditTailReq
	requireUnmarshal(t, fd.callsFor(ipc.OpAuditTail)[0].Body, &req)
	if req.Lines != 5 {
		t.Fatalf("Lines=%d", req.Lines)
	}
}

func TestRunAuditVerify_Intact(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{Total: 10, BadIndex: -1})
	if got := runAudit([]string{"verify"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditVerify_Broken(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{Total: 10, BadIndex: 5})
	if got := runAudit([]string{"verify"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditVerify_JSONIntact(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{Total: 5, BadIndex: -1})
	if got := runAudit([]string{"verify", "--json"}, cliScope{}); got != exitOK {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditVerify_JSONBroken(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{Total: 5, BadIndex: 2})
	if got := runAudit([]string{"verify", "--json"}, cliScope{}); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditVerify_BadFlag(t *testing.T) {
	if got := runAudit([]string{"verify", "--nope"}, cliScope{}); got != exitErr {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditVerify_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runAudit([]string{"verify"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d", got)
	}
}

func TestRunAuditReseal_NoBreak(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{BadIndex: -1, Total: 5})
	if got := runAudit([]string{"reseal"}, cliScope{}); got != exitOK {
		t.Fatalf("no-break reseal got %d, want exitOK", got)
	}
}

func TestRunAuditReseal_Scripted(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{BadIndex: 3, Total: 5})
	fd.onOK(ipc.OpAuditReseal, ipc.AuditResealResp{BrokenIndex: 3, Reason: "daemon restart", By: "uid=501 byn via socket"})
	if got := runAudit([]string{"reseal", "--reason", "daemon restart", "--yes"}, cliScope{}); got != exitOK {
		t.Fatalf("scripted reseal got %d, want exitOK", got)
	}
}

func TestRunAuditReseal_YesNeedsReason(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{BadIndex: 3, Total: 5})
	if got := runAudit([]string{"reseal", "--yes"}, cliScope{}); got != exitErr {
		t.Fatalf("--yes without --reason got %d, want exitErr", got)
	}
}

func TestRunAuditReseal_NoBreakAtResealTime(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditVerify, ipc.AuditVerifyResp{BadIndex: 3, Total: 5})
	fd.onOK(ipc.OpAuditReseal, ipc.AuditResealResp{NoBreak: true, BrokenIndex: -1})
	if got := runAudit([]string{"reseal", "--reason", "x", "--yes"}, cliScope{}); got != exitOK {
		t.Fatalf("no-break-at-reseal got %d, want exitOK", got)
	}
}

func TestConfirmReseal(t *testing.T) {
	cases := map[string]bool{"yes\n": true, "no\n": false, "\n": false, "y\n": false}
	for in, want := range cases {
		if got := confirmReseal(strings.NewReader(in), io.Discard); got != want {
			t.Errorf("confirmReseal(%q) = %v, want %v", in, got, want)
		}
	}
	// surrounding whitespace is trimmed.
	if !confirmReseal(strings.NewReader("  yes  \n"), io.Discard) {
		t.Error("confirmReseal should trim whitespace around yes")
	}
}

func TestPromptLine(t *testing.T) {
	if got := promptLine(strings.NewReader("daemon restart\n"), io.Discard, "p: "); got != "daemon restart" {
		t.Errorf("promptLine = %q", got)
	}
	if got := promptLine(strings.NewReader(""), io.Discard, "p: "); got != "" {
		t.Errorf("empty stdin should give empty, got %q", got)
	}
}

func TestRunAuditReseal_DaemonDown(t *testing.T) {
	noDaemon(t)
	if got := runAudit([]string{"reseal"}, cliScope{}); got != exitDaemonDown {
		t.Fatalf("got %d, want exitDaemonDown", got)
	}
}

func TestRunAuditTail_FilterFlagsAndIndex(t *testing.T) {
	fd := startFakeDaemon(t)
	fd.onOK(ipc.OpAuditTail, ipc.AuditTailResp{Events: []ipc.AuditEvent{{Index: 7, Op: "get", Outcome: "ok"}}})
	var code int
	out := captureStdout(t, func() {
		code = runAudit([]string{"tail", "--byn", "/a/.byn", "--scope", "alpha", "--caller", "byn"}, cliScope{})
	})
	if code != exitOK {
		t.Fatalf("filtered tail got %d, want exitOK", code)
	}
	if !strings.Contains(out, "#7") {
		t.Errorf("output should show event index #7, got: %s", out)
	}
	var req ipc.AuditTailReq
	requireUnmarshal(t, fd.callsFor(ipc.OpAuditTail)[0].Body, &req)
	if req.Byn != "/a/.byn" || req.Scope != "alpha" || req.Caller != "byn" {
		t.Errorf("filters not threaded to request: %+v", req)
	}
}

// TestRunAuditView_PaginatesFullDump: --lines 0 pages back through a log larger
// than one response, assembling all events oldest-first (the fix for the
// "ipc: read: EOF" on a full dump). The fake daemon serves 10-event pages keyed
// on the request Offset, mirroring the daemon's end-anchored windowing.
func TestRunAuditView_PaginatesFullDump(t *testing.T) {
	fd := startFakeDaemon(t)
	const total = 25
	fd.on(ipc.OpAuditTail, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.AuditTailReq
		_ = json.Unmarshal(raw, &req)
		end := total // exclusive upper index bound for this page
		if req.Before > 0 {
			end = req.Before
		}
		start := end - 10 // page size 10
		if start < 0 {
			start = 0
		}
		evs := make([]ipc.AuditEvent, 0, end-start)
		for i := start; i < end; i++ {
			evs = append(evs, ipc.AuditEvent{Index: i, Op: "get", Outcome: "ok"})
		}
		return ipc.AuditTailResp{Events: evs, Total: total, More: start > 0}, nil
	})

	var code int
	out := captureStdout(t, func() { code = runAudit([]string{"view", "--lines", "0"}, cliScope{}) })
	if code != exitOK {
		t.Fatalf("full dump exit %d", code)
	}
	for i := 0; i < total; i++ {
		if !strings.Contains(out, fmt.Sprintf("#%d ", i)) {
			t.Errorf("missing event #%d in the assembled dump", i)
		}
	}
	if strings.Index(out, "#0 ") > strings.Index(out, "#24 ") {
		t.Error("dump must be oldest-first (#0 before #24)")
	}
}

// TestRunAuditView_SinceConsumesForward: --since N consumes events newer than
// #N, oldest-first, paging forward by the max index seen (a program's
// reliable "fetch since last scanned" path).
func TestRunAuditView_SinceConsumesForward(t *testing.T) {
	fd := startFakeDaemon(t)
	const total = 25
	fd.on(ipc.OpAuditTail, func(raw []byte) (any, *ipc.ErrMsg) {
		var req ipc.AuditTailReq
		_ = json.Unmarshal(raw, &req)
		begin := req.Since + 1 // events with Index > Since
		if begin < 0 {
			begin = 0
		}
		end := begin + 10 // page size 10
		if end > total {
			end = total
		}
		evs := make([]ipc.AuditEvent, 0, end-begin)
		for i := begin; i < end; i++ {
			evs = append(evs, ipc.AuditEvent{Index: i, Op: "get", Outcome: "ok"})
		}
		return ipc.AuditTailResp{Events: evs, Total: total, More: end < total}, nil
	})

	var code int
	out := captureStdout(t, func() { code = runAudit([]string{"view", "--since", "4"}, cliScope{}) })
	if code != exitOK {
		t.Fatalf("since exit %d", code)
	}
	for i := 5; i < total; i++ { // #5..#24 across two forward pages
		if !strings.Contains(out, fmt.Sprintf("#%d ", i)) {
			t.Errorf("--since 4 missing #%d", i)
		}
	}
	if strings.Contains(out, "#4 ") || strings.Contains(out, "#0 ") {
		t.Error("--since 4 must exclude #4 and older")
	}
}
