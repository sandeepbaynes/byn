package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// fakeDaemon is a tiny in-process Unix-socket server that implements
// the minimum of the IPC protocol the cmd handlers need. Each test
// registers handlers per Op; unknown ops respond with an err envelope.
type fakeDaemon struct {
	t        *testing.T
	dir      string
	listener net.Listener

	mu       sync.Mutex
	handlers map[ipc.Op]func(reqRaw []byte) (any, *ipc.ErrMsg)
	calls    []recordedCall
}

type recordedCall struct {
	Op   ipc.Op
	Body []byte
}

// startFakeDaemon spins up a fake daemon listening on $dir/daemon.sock
// where $dir is a freshly created TempDir. It also sets BYN_TEST_DIR for
// the test so newClient(defaultDir()) targets the fake.
func startFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	// Use /tmp instead of t.TempDir() to dodge macOS' ~104 char limit on
	// Unix socket paths.
	dir, err := os.MkdirTemp("/tmp", "byn-fd-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sockPath := filepath.Join(dir, daemon.SocketFilename)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fd := &fakeDaemon{
		t:        t,
		dir:      dir,
		listener: l,
		handlers: make(map[ipc.Op]func([]byte) (any, *ipc.ErrMsg)),
	}
	t.Cleanup(func() { _ = l.Close() })
	go fd.serve()
	t.Setenv("BYN_TEST_DIR", dir)
	return fd
}

func (f *fakeDaemon) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handleConn(conn)
	}
}

func (f *fakeDaemon) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	env, err := ipc.ReadEnvelope(conn)
	if err != nil {
		return
	}
	f.mu.Lock()
	h, ok := f.handlers[env.Op]
	if ok {
		f.calls = append(f.calls, recordedCall{Op: env.Op, Body: append([]byte{}, env.Req...)})
	}
	f.mu.Unlock()
	if !ok {
		errResp := ipc.NewError(env.ID, ipc.CodeUnknownOp, "unknown op", "")
		_ = ipc.WriteFrame(conn, errResp)
		return
	}
	body, errMsg := h(env.Req)
	if errMsg != nil {
		_ = ipc.WriteFrame(conn, ipc.NewError(env.ID, errMsg.Code, errMsg.Message, errMsg.Recover))
		return
	}
	resp, err := ipc.NewResponse(env.ID, body)
	if err != nil {
		return
	}
	_ = ipc.WriteFrame(conn, resp)
}

// on registers a handler for op.
func (f *fakeDaemon) on(op ipc.Op, fn func(reqRaw []byte) (any, *ipc.ErrMsg)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[op] = fn
}

// onOK is a convenience for the empty-response success case.
func (f *fakeDaemon) onOK(op ipc.Op, body any) {
	f.on(op, func([]byte) (any, *ipc.ErrMsg) { return body, nil })
}

// onErr is a convenience to return a typed error.
func (f *fakeDaemon) onErr(op ipc.Op, code ipc.ErrCode, message string) {
	f.on(op, func([]byte) (any, *ipc.ErrMsg) {
		return nil, &ipc.ErrMsg{Code: code, Message: message}
	})
}

// callsFor returns the request bodies recorded for op.
func (f *fakeDaemon) callsFor(op ipc.Op) []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedCall
	for _, c := range f.calls {
		if c.Op == op {
			out = append(out, c)
		}
	}
	return out
}

// requireUnmarshal asserts the recorded request body decodes into v.
func requireUnmarshal(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// noDaemon sets BYN_TEST_DIR to a directory without a socket. Used to
// exercise the daemon-down branch.
func noDaemon(t *testing.T) {
	t.Helper()
	t.Setenv("BYN_TEST_DIR", t.TempDir())
}

// captureStderr redirects os.Stderr for the duration of fn and returns
// whatever was written to it. Uses a goroutine copier to avoid blocking
// if the pipe buffer fills before fn returns.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStderr: pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// errIs is a tiny helper preventing unused imports during refactors.
var _ = errors.Is
