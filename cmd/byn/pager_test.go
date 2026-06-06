package main

import (
	"os"
	"testing"
)

func TestShouldPage_NonStdout(t *testing.T) {
	if shouldPage(os.Stderr) {
		t.Fatal("non-stdout should never page")
	}
}

func TestShouldPage_DisabledByEnv(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "1")
	// stdout in test isn't a TTY anyway, but the explicit disable should short-circuit.
	if shouldPage(os.Stdout) {
		t.Fatal("BYN_NO_PAGER=1 should disable")
	}
}

func TestShouldPage_PAGEREqualsCat(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "")
	t.Setenv("PAGER", "cat")
	if shouldPage(os.Stdout) {
		t.Fatal("PAGER=cat should disable")
	}
}

func TestShouldPage_NonTTYStdout(t *testing.T) {
	t.Setenv("BYN_NO_PAGER", "")
	t.Setenv("PAGER", "")
	// stdout in test is not a TTY.
	if shouldPage(os.Stdout) {
		t.Fatal("non-TTY stdout should not page")
	}
}

func TestPickPager_HonorsPAGEREnv(t *testing.T) {
	t.Setenv("PAGER", "myless -SR")
	c := pickPager()
	if c == nil {
		t.Fatal("nil cmd")
	}
	if c.Path == "" {
		t.Fatal("empty path")
	}
}

func TestPickPager_WhitespaceOnlyPAGERIsNil(t *testing.T) {
	// PAGER set to whitespace is non-empty (skips fallback) but
	// strings.Fields returns no tokens → nil command.
	t.Setenv("PAGER", " ")
	if pickPager() != nil {
		t.Fatal("expected nil")
	}
}

func TestPickPager_EmptyPAGERFieldsNil(t *testing.T) {
	// PAGER set to literal empty string-with-spaces only would result in
	// strings.Fields returning nothing, so the function returns nil.
	t.Setenv("PAGER", "")
	// PAGER="" means env not set; let's check default lookup behavior.
	c := pickPager()
	// May be nil if no `less`/`more` on PATH; just ensure no panic.
	_ = c
}

func TestFprintPaged_WritesDirectlyWhenNotPaging(t *testing.T) {
	// With non-stdout writer, fprintPaged falls through to a direct write.
	tmp, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = tmp.Close() }()
	fprintPaged(tmp, "hello world\n")
	if err := tmp.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	body, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "hello world\n" {
		t.Fatalf("got %q", body)
	}
}
