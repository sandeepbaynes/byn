package daemon

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestAnnotateReadErr_DarwinEPERM: a TCC denial (EPERM) on macOS becomes an
// actionable Full Disk Access message AND is detectable via errDaemonAccessDenied
// (so exec surfaces the TCC cause instead of "untrusted"); other platforms pass
// the error through unchanged.
func TestAnnotateReadErr_DarwinEPERM(t *testing.T) {
	perr := &os.PathError{Op: "open", Path: "/Users/o/Documents/p/.byn", Err: syscall.EPERM}
	got := annotateReadErr(perr.Path, perr)
	if runtime.GOOS == "darwin" {
		if !strings.Contains(got.Error(), "Full Disk Access") {
			t.Errorf("EPERM on darwin must mention Full Disk Access; got %q", got)
		}
		if !strings.Contains(got.Error(), perr.Path) {
			t.Errorf("message should name the path; got %q", got)
		}
		if !errors.Is(got, errDaemonAccessDenied) {
			t.Errorf("EPERM on darwin must match errDaemonAccessDenied so exec can surface it")
		}
	} else if got != error(perr) {
		t.Errorf("non-darwin must return the error unchanged; got %v", got)
	}
}

// TestAnnotateReadErr_NotExistUnchanged: a not-exist error must pass through
// UNCHANGED so callers' os.IsNotExist(err) checks keep working.
func TestAnnotateReadErr_NotExistUnchanged(t *testing.T) {
	enoent := &os.PathError{Op: "open", Path: "/x/.byn", Err: syscall.ENOENT}
	got := annotateReadErr(enoent.Path, enoent)
	if got != error(enoent) {
		t.Fatalf("ENOENT must be returned unchanged; got %v", got)
	}
	if !os.IsNotExist(got) {
		t.Errorf("os.IsNotExist must still recognize the passed-through error")
	}
}
