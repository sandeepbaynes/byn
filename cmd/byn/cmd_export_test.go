package main

import (
	"strings"
	"testing"
)

func TestRenderDotenv_NoQuoteNeeded(t *testing.T) {
	keys := []string{"A", "B"}
	m := map[string]string{"A": "one", "B": "two"}
	got := renderDotenv(keys, m)
	if got != "A=one\nB=two\n" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderDotenv_QuotesValuesWithSpecials(t *testing.T) {
	cases := []struct {
		val string
	}{
		{"with space"},
		{"with\ttab"},
		{"with\nnl"},
		{"with\"quote"},
		{"with#hash"},
		{"with=eq"},
	}
	for _, tc := range cases {
		t.Run(tc.val, func(t *testing.T) {
			out := renderDotenv([]string{"K"}, map[string]string{"K": tc.val})
			if !strings.HasPrefix(out, "K=\"") {
				t.Fatalf("expected quoting, got %q", out)
			}
		})
	}
}

func TestRenderDotenv_EscapeBackslashAndQuote(t *testing.T) {
	out := renderDotenv([]string{"K"}, map[string]string{"K": `a\b"c`})
	if !strings.Contains(out, `\\`) {
		t.Fatalf("backslash not escaped: %q", out)
	}
	if !strings.Contains(out, `\"`) {
		t.Fatalf("quote not escaped: %q", out)
	}
}

func TestRenderDotenv_NewlineEscape(t *testing.T) {
	out := renderDotenv([]string{"K"}, map[string]string{"K": "a\nb"})
	// We expect quoting and \n escape.
	if !strings.Contains(out, `\n`) {
		t.Fatalf("newline not escaped to literal \\n: %q", out)
	}
}

func TestRenderDotenv_KeyOrderPreserved(t *testing.T) {
	keys := []string{"Z", "A", "M"}
	m := map[string]string{"Z": "1", "A": "2", "M": "3"}
	got := renderDotenv(keys, m)
	want := "Z=1\nA=2\nM=3\n"
	if got != want {
		t.Fatalf("order not preserved: %q", got)
	}
}
