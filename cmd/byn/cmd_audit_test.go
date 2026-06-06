package main

import (
	"encoding/json"
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
