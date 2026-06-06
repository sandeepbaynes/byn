package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/trust"
)

func TestTrustList_AndRemove(t *testing.T) {
	d, c := startTestDaemon(t)
	if err := trust.Save(d.cfg.Dir, &trust.Store{Records: []trust.Record{
		{Path: "/x/.byn", SHA256: "aa"},
		{Path: "/y/.byn", SHA256: "bb"},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var lr ipc.TrustListResp
	if err := c.Call(ipc.OpTrustList, ipc.TrustListReq{}, &lr); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(lr.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(lr.Entries))
	}

	var rr ipc.TrustRemoveResp
	if err := c.Call(ipc.OpTrustRemove, ipc.TrustRemoveReq{Path: "/x/.byn"}, &rr); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !rr.Removed {
		t.Error("expected removed=true")
	}

	lr = ipc.TrustListResp{}
	if err := c.Call(ipc.OpTrustList, ipc.TrustListReq{}, &lr); err != nil {
		t.Fatalf("list2: %v", err)
	}
	if len(lr.Entries) != 1 || lr.Entries[0].Path != "/y/.byn" {
		t.Fatalf("after remove: %+v", lr.Entries)
	}
}

func TestTrustList_Empty(t *testing.T) {
	_, c := startTestDaemon(t)
	var lr ipc.TrustListResp
	if err := c.Call(ipc.OpTrustList, ipc.TrustListReq{}, &lr); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(lr.Entries) != 0 {
		t.Fatalf("got %d entries, want 0", len(lr.Entries))
	}
}

func TestTrustRemove_EmptyPath(t *testing.T) {
	_, c := startTestDaemon(t)
	err := c.Call(ipc.OpTrustRemove, ipc.TrustRemoveReq{}, &ipc.TrustRemoveResp{})
	if code := errCode(t, err); code != ipc.CodeBadRequest {
		t.Fatalf("code = %v, want bad_request", code)
	}
}
