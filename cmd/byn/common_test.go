package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

func TestDefaultDir_EnvOverride(t *testing.T) {
	t.Setenv("BYN_DIR", "/tmp/explicit")
	got, err := defaultDir()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "/tmp/explicit" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultDir_HomeFallback(t *testing.T) {
	t.Setenv("BYN_DIR", "")
	got, err := defaultDir()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasSuffix(got, ".byn") {
		t.Fatalf("got %q, expected suffix .byn", got)
	}
}

func TestNewClient_SocketPath(t *testing.T) {
	c := newClient("/tmp/foo")
	want := filepath.Join("/tmp/foo", daemon.SocketFilename)
	if c.SocketPath != want {
		t.Fatalf("SocketPath = %q, want %q", c.SocketPath, want)
	}
}

func TestHandleCallError_NilIsOK(t *testing.T) {
	if got := handleCallError(nil); got != exitOK {
		t.Fatalf("nil should map to exitOK, got %d", got)
	}
}

func TestHandleCallError_DaemonDown(t *testing.T) {
	if got := handleCallError(ipc.ErrDaemonDown); got != exitDaemonDown {
		t.Fatalf("got %d, want %d", got, exitDaemonDown)
	}
	wrapped := errors.New("dial: " + ipc.ErrDaemonDown.Error())
	_ = wrapped
	// Wrap with errors.Is semantics.
	wrapped2 := errorsWrap(ipc.ErrDaemonDown)
	if got := handleCallError(wrapped2); got != exitDaemonDown {
		t.Fatalf("wrapped daemon down got %d", got)
	}
}

// errorsWrap returns an error whose chain contains target (for errors.Is).
type wrappedErr struct{ inner error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.inner.Error() }
func (w *wrappedErr) Unwrap() error { return w.inner }

func errorsWrap(inner error) error { return &wrappedErr{inner: inner} }

func TestHandleCallError_TypedErrResponse(t *testing.T) {
	e := &ipc.ErrResponse{Code: ipc.CodeNotFound, Message: "missing", Recover: "create it"}
	if got := handleCallError(e); got != exitDaemonErr {
		t.Fatalf("got %d, want %d", got, exitDaemonErr)
	}
	// Empty recover branch
	e2 := &ipc.ErrResponse{Code: ipc.CodeBadName, Message: "bad"}
	if got := handleCallError(e2); got != exitDaemonErr {
		t.Fatalf("got %d", got)
	}
}

func TestHandleCallError_GenericError(t *testing.T) {
	if got := handleCallError(errors.New("kaboom")); got != exitErr {
		t.Fatalf("got %d, want %d", got, exitErr)
	}
}

func TestZero_ClearsAllBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, want 0", i, v)
		}
	}
}
