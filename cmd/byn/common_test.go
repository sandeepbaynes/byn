package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// defaultDir returns the fixed per-OS system data root (internal/paths). Under
// the byntest build tag the test suite runs with, BYN_TEST_DIR repoints it so a
// test can isolate a tempdir; the old user-facing data-root override is gone.
func TestDefaultDir_TestSeamOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BYN_TEST_DIR", dir)
	got, err := defaultDir()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != dir {
		t.Fatalf("got %q, want %q", got, dir)
	}
}

// The removed user-facing data-root override is no longer honored — only the
// byntest seam (BYN_TEST_DIR) repoints defaultDir, and it wins.
func TestDefaultDir_LegacyOverrideNotHonored(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BYN_TEST_DIR", dir)
	t.Setenv("BYN"+"_DIR", "/tmp/should-be-ignored") // the removed override
	got, err := defaultDir()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != dir {
		t.Fatalf("legacy override leaked into defaultDir(): got %q, want %q", got, dir)
	}
}

func TestNewClient_SocketPath(t *testing.T) {
	c := newClient("/tmp/foo", "")
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

func TestMutateWithAuthRetry_CleanupCalledOnAuthRequired(t *testing.T) {
	// The cleanup func must be called when the call func returns isAuthRequiredErr.
	called := false
	cleanup := func() { called = true }
	authErr := &ipc.ErrResponse{Code: ipc.CodeAuthRequired, Message: "auth required"}
	got := mutateWithAuthRetry(false, true, false, cleanup, func(_ []byte) error {
		return authErr
	})
	// In jsonMode=true, no prompt — we get exitErr.
	if got != exitErr {
		t.Fatalf("got %d, want exitErr (%d)", got, exitErr)
	}
	if !called {
		t.Fatal("cleanupOnAuthRequired was not called")
	}
}

func TestMutateWithAuthRetry_CleanupCalledOnLocked(t *testing.T) {
	// The cleanup func must also be called when the call func returns isLockedErr.
	called := false
	cleanup := func() { called = true }
	lockedErr := &ipc.ErrResponse{Code: ipc.CodeLocked, Message: "vault is locked"}
	got := mutateWithAuthRetry(false, true, false, cleanup, func(_ []byte) error {
		return lockedErr
	})
	if got != exitErr {
		t.Fatalf("got %d, want exitErr (%d)", got, exitErr)
	}
	if !called {
		t.Fatal("cleanupOnAuthRequired was not called for locked error")
	}
}

func TestMutateWithAuthRetry_NilCleanup_NoLocked(t *testing.T) {
	// nil cleanup must not panic when a regular error occurs.
	got := mutateWithAuthRetry(false, false, false, nil, func(_ []byte) error {
		return errors.New("generic error")
	})
	if got == exitOK {
		t.Fatal("expected non-OK")
	}
}
