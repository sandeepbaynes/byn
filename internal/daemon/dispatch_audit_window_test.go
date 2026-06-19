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

func TestAuditPage_TailAndBefore(t *testing.T) {
	all := mkAudit(100) // indices 0..99
	// Tail (no cursor): newest 10 → #90..#99, more older remain.
	w, more := auditPage(all, 10, 0, 0)
	if len(w) != 10 || w[0].Index != 90 || w[9].Index != 99 || !more {
		t.Fatalf("tail: len=%d first=%d last=%d more=%v", len(w), w[0].Index, w[len(w)-1].Index, more)
	}
	// Backward cursor: Index < 90, newest 10 → #80..#89, more remain.
	w, more = auditPage(all, 10, 90, 0)
	if len(w) != 10 || w[0].Index != 80 || w[9].Index != 89 || !more {
		t.Fatalf("before 90: first=%d last=%d more=%v", w[0].Index, w[len(w)-1].Index, more)
	}
	// Backward to the start: Index < 10 → #0..#9, more=false.
	w, more = auditPage(all, 10, 10, 0)
	if len(w) != 10 || w[0].Index != 0 || w[9].Index != 9 || more {
		t.Fatalf("before 10: first=%d last=%d more=%v (want more=false)", w[0].Index, w[len(w)-1].Index, more)
	}
}

func TestAuditPage_Since(t *testing.T) {
	all := mkAudit(100)
	// Forward cursor: Index > 50, oldest 10 → #51..#60, more newer remain.
	w, more := auditPage(all, 10, 0, 50)
	if len(w) != 10 || w[0].Index != 51 || w[9].Index != 60 || !more {
		t.Fatalf("since 50: first=%d last=%d more=%v", w[0].Index, w[len(w)-1].Index, more)
	}
	// Forward near the end: Index > 95 → #96..#99, more=false.
	w, more = auditPage(all, 10, 0, 95)
	if len(w) != 4 || w[0].Index != 96 || w[3].Index != 99 || more {
		t.Fatalf("since 95: len=%d first=%d last=%d more=%v", len(w), w[0].Index, w[len(w)-1].Index, more)
	}
	// Nothing newer than the newest.
	if w, more := auditPage(all, 10, 0, 99); len(w) != 0 || more {
		t.Fatalf("since 99: len=%d more=%v (want empty)", len(w), more)
	}
}

// TestAuditPage_StableUnderGrowth is the reliability property the owner asked
// for: a Before-cursor page returns the SAME events even after the log grows
// (appended events get higher indices and are never < Before).
func TestAuditPage_StableUnderGrowth(t *testing.T) {
	before, _ := auditPage(mkAudit(50), 10, 30, 0) // #20..#29
	after, _ := auditPage(mkAudit(80), 10, 30, 0)  // 30 events appended since
	if len(before) != len(after) {
		t.Fatalf("page size changed under growth: %d vs %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Index != after[i].Index {
			t.Fatalf("before-cursor page shifted under growth at %d: %d vs %d", i, before[i].Index, after[i].Index)
		}
	}
}

// TestAuditPage_SizeBudget: with large events the page is capped by the byte
// budget (not the count), stays the NEWEST slice, and fits in one IPC frame.
func TestAuditPage_SizeBudget(t *testing.T) {
	big := strings.Repeat("x", 4096) // ~4 KiB per event
	all := make([]audit.Event, 1000)
	for i := range all {
		all[i] = audit.Event{Op: "exec", Outcome: "ok", Command: big}
		all[i].Index = i
	}
	w, more := auditPage(all, 0, 0, 0)
	if len(w) == 0 || len(w) >= 1000 || !more {
		t.Fatalf("budget should cap below 1000 large events with more=true, got len=%d more=%v", len(w), more)
	}
	if w[len(w)-1].Index != 999 {
		t.Fatalf("page must end at the newest event, got last index %d", w[len(w)-1].Index)
	}
	wire := make([]ipc.AuditEvent, len(w))
	for i, e := range w {
		wire[i] = auditToWire(e)
		wire[i].Index = e.Index
	}
	b, _ := json.Marshal(ipc.AuditTailResp{Events: wire, Total: 1000, More: more})
	if len(b) >= int(ipc.MaxFrameSize) {
		t.Fatalf("page marshaled to %d bytes, must be under MaxFrameSize %d", len(b), ipc.MaxFrameSize)
	}
}
