package ipc

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClient_Defaults(t *testing.T) {
	c := NewClient("/sock")
	if c.SocketPath != "/sock" {
		t.Fatalf("SocketPath=%q", c.SocketPath)
	}
	if c.Timeout != DefaultClientTimeout {
		t.Fatalf("Timeout=%v", c.Timeout)
	}
}

func TestErrResponse_Error_WithRecover(t *testing.T) {
	e := &ErrResponse{Code: CodeNotFound, Message: "missing", Recover: "create"}
	if !strings.Contains(e.Error(), "missing") || !strings.Contains(e.Error(), "create") {
		t.Fatalf("Error=%q", e.Error())
	}
}

func TestErrResponse_Error_NoRecover(t *testing.T) {
	e := &ErrResponse{Code: CodeBadName, Message: "bad"}
	if !strings.Contains(e.Error(), "bad") || !strings.Contains(e.Error(), string(CodeBadName)) {
		t.Fatalf("Error=%q", e.Error())
	}
}

func TestClient_Call_DaemonDown(t *testing.T) {
	c := NewClient(filepath.Join(t.TempDir(), "no.sock"))
	c.Timeout = time.Second
	err := c.Call(OpStatus, StatusReq{}, &StatusResp{})
	if err == nil || !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("err = %v, want ErrDaemonDown", err)
	}
}

// shortTempDir returns a temporary directory whose path is short enough to hold
// a unix socket.
//
// sun_path is 104 bytes on macOS and 108 on Linux — a limit on the PATH, not on
// the directory, so it is easy to exceed by accident. t.TempDir() on macOS
// hands back /var/folders/<32 chars>/T/<TestName>/001, which is already past it
// once a filename is appended. The guard that used to sit here called itself
// defensive and fired on every single macOS run instead, silently disabling
// these tests on that platform rather than in the rare case it was written for.
//
// /tmp explicitly, NOT os.MkdirTemp's default: that default is $TMPDIR, which is
// the long per-user path on macOS and would reintroduce exactly the problem.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "byn")
	if err != nil {
		return t.TempDir() // no /tmp: fall back and let the caller's guard decide
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeServer is a one-shot stub answering with cb on the first conn.
func fakeServer(t *testing.T, cb func(env *Envelope) *Envelope) string {
	t.Helper()
	sockPath := filepath.Join(shortTempDir(t), "s.sock")
	if len(sockPath) > 100 {
		t.Skipf("socket path too long: %d", len(sockPath))
	}
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				env, err := ReadEnvelope(c)
				if err != nil {
					return
				}
				resp := cb(env)
				if resp != nil {
					_ = WriteFrame(c, resp)
				}
			}(conn)
		}
	}()
	return sockPath
}

func TestClient_Call_RoundTrip(t *testing.T) {
	sockPath := fakeServer(t, func(env *Envelope) *Envelope {
		r, _ := NewResponse(env.ID, StatusResp{Version: "test"})
		return r
	})
	c := NewClient(sockPath)
	c.Timeout = 2 * time.Second
	var resp StatusResp
	if err := c.Call(OpStatus, StatusReq{}, &resp); err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Version != "test" {
		t.Fatalf("Version=%q", resp.Version)
	}
}

func TestClient_Call_DaemonErrResponse(t *testing.T) {
	sockPath := fakeServer(t, func(env *Envelope) *Envelope {
		return NewError(env.ID, CodeNotFound, "no", "create it")
	})
	c := NewClient(sockPath)
	c.Timeout = 2 * time.Second
	err := c.Call(OpGet, GetReq{}, &GetResp{})
	var er *ErrResponse
	if !errors.As(err, &er) {
		t.Fatalf("err type: %T", err)
	}
	if er.Code != CodeNotFound {
		t.Fatalf("Code=%v", er.Code)
	}
}

func TestClient_Call_IDMismatch(t *testing.T) {
	sockPath := fakeServer(t, func(env *Envelope) *Envelope {
		// Reply with a different ID than the request.
		r, _ := NewResponse("WRONG-ID", StatusResp{})
		return r
	})
	c := NewClient(sockPath)
	c.Timeout = 2 * time.Second
	err := c.Call(OpStatus, StatusReq{}, &StatusResp{})
	if err == nil || !strings.Contains(err.Error(), "id mismatch") {
		t.Fatalf("err = %v", err)
	}
}

func TestClient_Call_NilResp(t *testing.T) {
	sockPath := fakeServer(t, func(env *Envelope) *Envelope {
		r, _ := NewResponse(env.ID, struct{}{})
		return r
	})
	c := NewClient(sockPath)
	c.Timeout = 2 * time.Second
	if err := c.Call(OpStatus, StatusReq{}, nil); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestClient_Call_ServerNeverReplies(t *testing.T) {
	sockPath := fakeServer(t, func(_ *Envelope) *Envelope { return nil })
	c := NewClient(sockPath)
	c.Timeout = 200 * time.Millisecond
	err := c.Call(OpStatus, StatusReq{}, &StatusResp{})
	if err == nil {
		t.Fatal("expected timeout/read err")
	}
}

func TestClient_Call_TimeoutZeroUsesDefault(t *testing.T) {
	sockPath := fakeServer(t, func(env *Envelope) *Envelope {
		r, _ := NewResponse(env.ID, StatusResp{})
		return r
	})
	c := &Client{SocketPath: sockPath, Timeout: 0}
	if err := c.Call(OpStatus, StatusReq{}, &StatusResp{}); err != nil {
		t.Fatalf("err: %v", err)
	}
}
