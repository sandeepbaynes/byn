package auth

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestPrompt_NoTerminal(t *testing.T) {
	// Pipe fd is never a terminal.
	r, _, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close() }()
	var buf bytes.Buffer
	_, err = Prompt(int(r.Fd()), &buf, "pw> ")
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err=%v, want ErrNoTerminal", err)
	}
}

func TestPromptStdin_NotATerminal(t *testing.T) {
	// In `go test` os.Stdin is generally not a TTY.
	_, err := PromptStdin("password> ")
	if !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("err=%v, want ErrNoTerminal", err)
	}
}
