package main

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/sandeepbaynes/byn/internal/auth"
)

// PromptTTY must read from the terminal even while stdin holds unread data —
// and must not consume that data, which is the value being stored.
func TestPromptTTY_ReadsTheTerminalAndLeavesStdinAlone(t *testing.T) {
	ptmx, pts := openPTY(t)
	defer func() { _ = ptmx.Close() }()
	defer func() { _ = pts.Close() }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	const value = "the-secret-value"
	_, _ = w.WriteString(value)
	_ = w.Close()

	prevIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = prev(prevIn) }()

	// A prompt on the pty while stdin is the pipe.
	type res struct {
		pw  []byte
		err error
	}
	done := make(chan res, 1)
	go func() {
		pw, err := auth.Prompt(int(pts.Fd()), pts, "Master password: ")
		done <- res{pw, err}
	}()
	time.Sleep(300 * time.Millisecond)
	if _, werr := ptmx.Write([]byte("master-pw\n")); werr != nil {
		t.Fatalf("write to pty: %v", werr)
	}
	var got res
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prompt never returned")
	}
	if got.err != nil {
		t.Fatalf("prompt: %v", got.err)
	}
	if string(got.pw) != "master-pw" {
		t.Fatalf("read %q from the terminal, want master-pw", got.pw)
	}

	// The value is still on stdin, untouched. If the prompt had read stdin it
	// would have eaten the secret being stored.
	rest := make([]byte, 64)
	n, _ := os.Stdin.Read(rest)
	if !bytes.Equal(rest[:n], []byte(value)) {
		t.Fatalf("stdin was disturbed: got %q, want %q", rest[:n], value)
	}
}

func prev(f *os.File) *os.File { return f }
