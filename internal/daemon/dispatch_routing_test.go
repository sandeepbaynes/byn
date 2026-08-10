package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestDispatch_UnknownOpRejected pins the dispatch routing table's default
// arm: an op the daemon does not recognize is rejected with CodeUnknownOp and
// an "unknown op" message — never silently dropped or mis-routed.
func TestDispatch_UnknownOpRejected(t *testing.T) {
	_, c := startTestDaemon(t)
	err := c.Call(ipc.Op("bogus.nonexistent"), struct{}{}, &struct{}{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("unknown op err = %v, want *ipc.ErrResponse", err)
	}
	if er.Code != ipc.CodeUnknownOp {
		t.Fatalf("Code = %v, want %v", er.Code, ipc.CodeUnknownOp)
	}
	if !strings.Contains(strings.ToLower(er.Message), "unknown op") {
		t.Fatalf("Message = %q, want it to mention %q", er.Message, "unknown op")
	}
}

// TestDispatch_KnownOpRouted confirms a known op (status) is routed to its
// handler rather than falling through to the unknown-op arm — the positive
// counterpart to the routing-table test above.
func TestDispatch_KnownOpRouted(t *testing.T) {
	_, c := startTestDaemon(t)
	var resp ipc.StatusResp
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &resp); err != nil {
		t.Fatalf("status: %v", err)
	}
}
