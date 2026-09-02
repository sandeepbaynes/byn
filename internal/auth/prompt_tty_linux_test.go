package auth

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestHaveTerminal_PipedStdinWithAControllingTerminal is the reported bug:
//
//	echo "Example <noreply@example.test>" | byn put EMAIL_FROM
//	Error: this action requires authorization (run `byn unlock` …)
//
// The value arrived on stdin, so stdin was a pipe, so byn decided nobody was
// there and told the person in front of it to go run another command. stdin
// says how data arrived; it does not say whether anybody is present.
func TestHaveTerminal_PipedStdinWithAControllingTerminal(t *testing.T) {
	ptmx, pts := openTestPTY(t)
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = pts.Close() }()
	withTTY(t, pts)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	_ = w.Close()

	if HaveTerminal(int(r.Fd())) != true {
		t.Fatal("a piped stdin with a controlling terminal present must still be promptable")
	}
}

// And the honest negative: no controlling terminal means nobody to ask, so the
// caller reports the refusal rather than hanging on a prompt that cannot be
// answered. This is the cron/container/CI case.
func TestHaveTerminal_NoControllingTerminal(t *testing.T) {
	withTTYError(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	_ = w.Close()

	if HaveTerminal(int(r.Fd())) {
		t.Fatal("no controlling terminal must report nobody to ask")
	}
	if _, err := PromptTTY("Master password: "); err != ErrNoTerminal {
		t.Fatalf("want ErrNoTerminal, got %v", err)
	}
}

// The lead lines must reach the terminal, not stderr: a caller redirecting
// stderr should not have the reason it is being asked land in the redirect
// while a bare prompt waits on screen.
func TestPromptTTY_WritesItsContextToTheTerminal(t *testing.T) {
	ptmx, pts := openTestPTY(t)
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = pts.Close() }()
	withTTY(t, pts)

	done := make(chan error, 1)
	go func() {
		buf, err := PromptTTYSecureWithLead("Master password: ", []string{"Authorization required."})
		if buf != nil {
			buf.Wipe()
		}
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if _, err := ptmx.Write([]byte("pw\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("prompt: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prompt never returned")
	}
	_ = ptmx.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	out := make([]byte, 4096)
	n, _ := ptmx.Read(out)
	if !bytes.Contains(out[:n], []byte("Authorization required.")) {
		t.Fatalf("the lead-in must go to the terminal with the prompt, got %q", out[:n])
	}
}

func withTTY(t *testing.T, f *os.File) {
	t.Helper()
	prevOpen := openTTY
	openTTY = func() (*os.File, error) { return f, nil }
	t.Cleanup(func() { openTTY = prevOpen })
}

func withTTYError(t *testing.T) {
	t.Helper()
	prevOpen := openTTY
	openTTY = func() (*os.File, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { openTTY = prevOpen })
}

func openTestPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = ptmx.Close()
		t.Skipf("TIOCGPTN: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = ptmx.Close()
		t.Skipf("unlockpt: %v", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Skipf("open pts: %v", err)
	}
	return ptmx, pts
}
