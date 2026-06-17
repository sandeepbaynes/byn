package bynfile

import "testing"

func TestParse_ExecWritable(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"X\"]\nactions = [\"pnpm dev\"]\nwritable = [\"~/Library/pnpm\", \"~/.cache\"]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Exec.Writable) != 2 || f.Exec.Writable[0] != "~/Library/pnpm" || f.Exec.Writable[1] != "~/.cache" {
		t.Errorf("Writable = %v, want [~/Library/pnpm ~/.cache]", f.Exec.Writable)
	}
}

func TestParse_ExecWritableAbsent(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"X\"]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Exec.Writable != nil {
		t.Errorf("absent [exec] writable must be nil, got %v", f.Exec.Writable)
	}
}
