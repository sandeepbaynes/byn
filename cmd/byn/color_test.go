package main

import (
	"strings"
	"testing"
)

// withUseColor temporarily forces useColor for a test, restoring the
// prior value via t.Cleanup.
func withUseColor(t *testing.T, v bool) {
	t.Helper()
	prev := useColor
	useColor = v
	t.Cleanup(func() { useColor = prev })
}

func TestWrap_PassthroughWhenColorOff(t *testing.T) {
	withUseColor(t, false)
	if got := wrap(ansiRed, "hello"); got != "hello" {
		t.Fatalf("wrap off should passthrough, got %q", got)
	}
}

func TestWrap_AddsCodesWhenColorOn(t *testing.T) {
	withUseColor(t, true)
	got := wrap(ansiRed, "hello")
	if !strings.HasPrefix(got, ansiRed) || !strings.HasSuffix(got, ansiReset) {
		t.Fatalf("wrap on missing codes, got %q", got)
	}
	if !strings.Contains(got, "hello") {
		t.Fatalf("wrap dropped payload, got %q", got)
	}
}

func TestColorHelpers_AllExercised(t *testing.T) {
	withUseColor(t, true)
	helpers := map[string]func(string) string{
		"red":        red,
		"yellow":     yellow,
		"cyan":       cyan,
		"bold":       bold,
		"dim":        dim,
		"boldRed":    boldRed,
		"boldYellow": boldYellow,
	}
	for name, fn := range helpers {
		got := fn("x")
		if !strings.Contains(got, "x") {
			t.Fatalf("%s: lost payload %q", name, got)
		}
		if !strings.Contains(got, ansiReset) {
			t.Fatalf("%s: missing reset %q", name, got)
		}
	}
}

func TestComputeUseColor_NoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "")
	if computeUseColor() {
		t.Fatal("NO_COLOR should win")
	}
}

func TestComputeUseColor_ForceColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	if !computeUseColor() {
		t.Fatal("FORCE_COLOR should force on")
	}
}

func TestComputeUseColor_DefaultDependsOnTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	// stderr in the test binary is not a TTY → should be false.
	if computeUseColor() {
		t.Fatal("non-TTY stderr should yield false")
	}
}
