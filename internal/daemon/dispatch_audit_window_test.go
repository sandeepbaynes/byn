package daemon

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

func mkAudit(n int) []audit.Event {
	all := make([]audit.Event, n)
	for i := range all {
		all[i] = audit.Event{Op: "get", Outcome: "ok"}
		all[i].Index = i
	}
	return all
}

func TestAuditWindow_OffsetAndTail(t *testing.T) {
	all := mkAudit(100)
	// Tail (offset 0): last 10 → indices 90..99, oldest-first.
	w := auditWindow(all, 10, 0)
	if len(w) != 10 || w[0].Index != 90 || w[9].Index != 99 {
		t.Fatalf("tail 10: len=%d first=%d last=%d", len(w), w[0].Index, w[len(w)-1].Index)
	}
	// Page back: offset 10, lines 10 → indices 80..89.
	w = auditWindow(all, 10, 10)
	if len(w) != 10 || w[0].Index != 80 || w[9].Index != 89 {
		t.Fatalf("offset 10: first=%d last=%d", w[0].Index, w[len(w)-1].Index)
	}
	// lines<=0 on a small log → everything.
	w = auditWindow(all, 0, 0)
	if len(w) != 100 || w[0].Index != 0 || w[99].Index != 99 {
		t.Fatalf("all: len=%d", len(w))
	}
	// Offset beyond total → empty.
	if w := auditWindow(all, 10, 200); len(w) != 0 {
		t.Fatalf("offset beyond total: len=%d", len(w))
	}
}

// TestAuditWindow_SizeBudget: with large events the page is capped by the byte
// budget (not the count), stays the NEWEST slice, and fits in one IPC frame.
func TestAuditWindow_SizeBudget(t *testing.T) {
	big := strings.Repeat("x", 4096) // ~4 KiB per event
	all := make([]audit.Event, 1000)
	for i := range all {
		all[i] = audit.Event{Op: "exec", Outcome: "ok", Command: big}
		all[i].Index = i
	}
	w := auditWindow(all, 0, 0)
	if len(w) == 0 || len(w) >= 1000 {
		t.Fatalf("budget should cap below 1000 large events, got %d", len(w))
	}
	if w[len(w)-1].Index != 999 {
		t.Fatalf("page must end at the newest event, got last index %d", w[len(w)-1].Index)
	}
	wire := make([]ipc.AuditEvent, len(w))
	for i, e := range w {
		wire[i] = auditToWire(e)
		wire[i].Index = e.Index
	}
	b, _ := json.Marshal(ipc.AuditTailResp{Events: wire, Total: 1000})
	if len(b) >= int(ipc.MaxFrameSize) {
		t.Fatalf("page marshaled to %d bytes, must be under MaxFrameSize %d", len(b), ipc.MaxFrameSize)
	}
}
