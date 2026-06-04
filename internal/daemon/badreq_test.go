package daemon

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// sendBadEnvelope dials the daemon socket and sends a malformed-body
// envelope for op. The daemon should respond with bad_request /
// unknown_op depending on the op.
func sendBadEnvelope(t *testing.T, sockPath string, op ipc.Op, malformedJSON []byte) *ipc.Envelope {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	env := &ipc.Envelope{V: ipc.ProtocolVersion, ID: "bad-id", Op: op, Req: malformedJSON}
	if err := ipc.WriteFrame(conn, env); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := ipc.ReadEnvelope(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return resp
}

func TestDispatch_BadBodyReturnsBadRequest(t *testing.T) {
	d, _ := startTestDaemon(t)
	// Bodies that don't unmarshal into the op's request type.
	cases := []ipc.Op{
		ipc.OpVaultInit, ipc.OpVaultUnlock, ipc.OpVaultLock,
		ipc.OpProjectCreate, ipc.OpProjectList, ipc.OpProjectDelete, ipc.OpProjectRename,
		ipc.OpEnvCreate, ipc.OpEnvList, ipc.OpEnvDelete, ipc.OpEnvRename,
		ipc.OpPut, ipc.OpGet, ipc.OpList, ipc.OpDelete, ipc.OpRename,
		ipc.OpAuditTail, ipc.OpAuditVerify, ipc.OpVaultDelete,
	}
	for _, op := range cases {
		t.Run(string(op), func(t *testing.T) {
			resp := sendBadEnvelope(t, d.SocketPath(), op, []byte(`not-json`))
			if resp.Err == nil {
				t.Fatalf("op %s: expected err", op)
			}
			// Either CodeBadRequest or, in handleVaultDelete's stub,
			// CodeUnknownOp. Both are acceptable per-handler.
			if resp.Err.Code != ipc.CodeBadRequest && resp.Err.Code != ipc.CodeUnknownOp {
				t.Fatalf("op %s: Code=%v", op, resp.Err.Code)
			}
		})
	}
}

func TestDispatch_UnknownOpReturnsUnknownOp(t *testing.T) {
	d, _ := startTestDaemon(t)
	resp := sendBadEnvelope(t, d.SocketPath(), "no.such.op", []byte("{}"))
	if resp.Err == nil || resp.Err.Code != ipc.CodeUnknownOp {
		t.Fatalf("err = %+v", resp.Err)
	}
}

func TestVaultUnlock_WithoutInit(t *testing.T) {
	_, c := startTestDaemon(t)
	err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: []byte("pw")}, &ipc.VaultUnlockResp{})
	var er *ipc.ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("err = %v", err)
	}
	// Could be NotInit or WrongPassword (both convey "no" without
	// leaking which).
	if er.Code != ipc.CodeWrongPassword && er.Code != ipc.CodeNotInit {
		t.Fatalf("Code = %v", er.Code)
	}
}
