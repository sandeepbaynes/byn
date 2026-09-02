package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPromptSecretValue_ReadsTheValueWithoutEchoingIt drives a real pty.
//
// A pty is the only place this behaviour exists. The whole point of the prompt
// is that the terminal does not echo what is typed, and echo is a property of
// the terminal line discipline — a test with a pipe for stdin cannot observe it
// either way, and would pass just as happily against code that echoed the
// secret across the screen.
func TestPromptSecretValue_ReadsTheValueWithoutEchoingIt(t *testing.T) {
	ptmx, pts := openPTY(t)
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = pts.Close() }()

	prevIn, prevErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = pts, pts
	defer func() { os.Stdin, os.Stderr = prevIn, prevErr }()

	const secret = "hunter2-not-echoed"
	type result struct {
		val []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := promptSecretValue("DB_URL")
		done <- result{v, err}
	}()

	// Let the prompt disable echo before anything is typed. Typing first would
	// race the line discipline and test nothing reliable.
	time.Sleep(300 * time.Millisecond)
	if _, err := ptmx.Write([]byte(secret + "\n")); err != nil {
		t.Fatalf("write to pty: %v", err)
	}

	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("promptSecretValue never returned")
	}
	if got.err != nil {
		t.Fatalf("prompt: %v", got.err)
	}
	if string(got.val) != secret {
		t.Fatalf("read %q, want %q", got.val, secret)
	}

	// What the terminal sent back. The prompt itself is expected here; the
	// secret is not.
	_ = ptmx.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _ := ptmx.Read(buf)
	echoed := buf[:n]
	if bytes.Contains(echoed, []byte(secret)) {
		t.Fatalf("the value was echoed to the terminal: %q", echoed)
	}
	if !bytes.Contains(echoed, []byte("DB_URL")) {
		t.Errorf("the prompt should name the variable, got %q", echoed)
	}
	// An unexplained silent cursor reads as a hung program, and the reflex is
	// to press keys until something happens.
	if !bytes.Contains(echoed, []byte("hidden")) {
		t.Errorf("the prompt should say input is hidden, got %q", echoed)
	}
}

// An empty entry is almost always a stray Enter, and must not silently store an
// empty value over a real one.
func TestPromptSecretValue_RefusesAnEmptyEntry(t *testing.T) {
	ptmx, pts := openPTY(t)
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = pts.Close() }()

	prevIn, prevErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = pts, pts
	defer func() { os.Stdin, os.Stderr = prevIn, prevErr }()

	errc := make(chan error, 1)
	go func() {
		_, err := promptSecretValue("DB_URL")
		errc <- err
	}()
	time.Sleep(300 * time.Millisecond)
	if _, err := ptmx.Write([]byte("\n")); err != nil {
		t.Fatalf("write to pty: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("an empty entry must not be accepted")
		}
		// It is a legitimate value, so the way to store one deliberately has to
		// be in the message.
		if !bytes.Contains([]byte(err.Error()), []byte("byn put DB_URL")) {
			t.Errorf("the error must name how to store an empty value on purpose: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("promptSecretValue never returned")
	}
}

// openPTY returns a connected (master, slave) pair.
func openPTY(t *testing.T) (*os.File, *os.File) {
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
