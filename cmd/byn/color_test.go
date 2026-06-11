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

// withUseColorStdout temporarily forces useColorStdout for a test, restoring
// the prior value via t.Cleanup.
func withUseColorStdout(t *testing.T, v bool) {
	t.Helper()
	prev := useColorStdout
	useColorStdout = v
	t.Cleanup(func() { useColorStdout = prev })
}

func TestColorizeDiff_PassthroughWhenColorOff(t *testing.T) {
	withUseColorStdout(t, false)
	in := "--- trusted\n+++ current\n@@ -1 +1 @@\n-old\n+new\n"
	if got := colorizeDiff(in); got != in {
		t.Fatalf("color off should passthrough, got %q", got)
	}
}

func TestColorizeDiff_AppliesGitColors(t *testing.T) {
	withUseColorStdout(t, true)
	in := "--- trusted\n+++ current\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
	lines := strings.Split(colorizeDiff(in), "\n")
	// 0:--- header bold, 1:+++ header bold, 2:@@ cyan, 3:context plain,
	// 4:-old red, 5:+new green, 6:"" trailing (unchanged).
	if !strings.HasPrefix(lines[0], ansiBold) || !strings.HasPrefix(lines[1], ansiBold) {
		t.Fatalf("file headers should be bold: %q / %q", lines[0], lines[1])
	}
	// File headers must NOT be misread as removed/added content lines.
	if strings.Contains(lines[0], ansiRed) || strings.Contains(lines[1], ansiGreen) {
		t.Fatalf("file headers misclassified as content: %q / %q", lines[0], lines[1])
	}
	if !strings.HasPrefix(lines[2], ansiCyan) {
		t.Fatalf("hunk header should be cyan: %q", lines[2])
	}
	if lines[3] != " context" {
		t.Fatalf("context line should be untouched: %q", lines[3])
	}
	if !strings.HasPrefix(lines[4], ansiRed) {
		t.Fatalf("removed line should be red: %q", lines[4])
	}
	if !strings.HasPrefix(lines[5], ansiGreen) {
		t.Fatalf("added line should be green: %q", lines[5])
	}
	if lines[6] != "" {
		t.Fatalf("trailing line should stay empty, got %q", lines[6])
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
