package site

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitFrontMatter_Fenced(t *testing.T) {
	src := "---\ntitle: Security model\ndescription: Threat model.\nnav_order: 3\nsection: Reference\n---\n# Heading\n\nBody text.\n"
	fm, body := SplitFrontMatter(src)

	assert.Equal(t, "Security model", fm.Title)
	assert.Equal(t, "Threat model.", fm.Description)
	assert.Equal(t, "Reference", fm.Section)
	require.True(t, fm.HasNavOrder())
	assert.Equal(t, 3, fm.NavOrder)
	assert.Equal(t, "# Heading\n\nBody text.\n", body)
}

func TestSplitFrontMatter_FencedQuotedValues(t *testing.T) {
	src := "---\ntitle: \"Quoted Title\"\ndescription: 'single quoted'\n---\nbody"
	fm, body := SplitFrontMatter(src)

	assert.Equal(t, "Quoted Title", fm.Title)
	assert.Equal(t, "single quoted", fm.Description)
	assert.Equal(t, "body", body)
}

func TestSplitFrontMatter_BareKeyBlock(t *testing.T) {
	src := "title: Bare Title\ndescription: A bare block.\n\n# Real H1\n\nText."
	fm, body := SplitFrontMatter(src)

	assert.Equal(t, "Bare Title", fm.Title)
	assert.Equal(t, "A bare block.", fm.Description)
	assert.Equal(t, "# Real H1\n\nText.", body)
}

func TestSplitFrontMatter_NoFrontMatter(t *testing.T) {
	// The graceful-degradation path: a normal doc with an H1 and a horizontal
	// rule (the "---" after prose) must NOT be treated as front matter.
	src := "# Security model\n\nWhat byn defends against.\n\n---\n\n## Section\n\nMore."
	fm, body := SplitFrontMatter(src)

	assert.Empty(t, fm.Title)
	assert.Empty(t, fm.Description)
	assert.False(t, fm.HasNavOrder())
	assert.Equal(t, src, body, "body must be returned unchanged when no front matter")
}

func TestSplitFrontMatter_HorizontalRuleNotConsumed(t *testing.T) {
	// A leading "---" that is a thematic break (followed by content, not a key
	// block) must not be mistaken for an opening fence.
	src := "---\n\nJust a horizontal rule, no keys.\n"
	fm, body := SplitFrontMatter(src)
	assert.Empty(t, fm.Title)
	assert.Equal(t, src, body)
}

func TestSplitFrontMatter_FirstLineNotAKeyIsIgnored(t *testing.T) {
	// A doc starting with prose that happens to contain a colon must not be
	// parsed as a bare key block.
	src := "This is prose: with a colon.\n\nMore."
	fm, body := SplitFrontMatter(src)
	assert.Empty(t, fm.Title)
	assert.Equal(t, src, body)
}

func TestSplitFrontMatter_UnknownKeysIgnored(t *testing.T) {
	src := "---\ntitle: T\nauthor: nobody\n---\nbody"
	fm, _ := SplitFrontMatter(src)
	assert.Equal(t, "T", fm.Title)
	assert.Empty(t, fm.Section)
}

func TestSplitFrontMatter_LeadingBlankLines(t *testing.T) {
	src := "\n\n---\ntitle: T\n---\nbody"
	fm, body := SplitFrontMatter(src)
	assert.Equal(t, "T", fm.Title)
	assert.Equal(t, "body", body)
}

func TestSplitFrontMatter_InvalidNavOrderIgnored(t *testing.T) {
	src := "---\ntitle: T\nnav_order: notanumber\n---\nbody"
	fm, _ := SplitFrontMatter(src)
	assert.Equal(t, "T", fm.Title)
	assert.False(t, fm.HasNavOrder())
}

func TestSplitFrontMatter_NegativeNavOrder(t *testing.T) {
	src := "---\nnav_order: -2\n---\nbody"
	fm, _ := SplitFrontMatter(src)
	require.True(t, fm.HasNavOrder())
	assert.Equal(t, -2, fm.NavOrder)
}

func TestAtoi(t *testing.T) {
	cases := map[string]struct {
		in   string
		want int
		ok   bool
	}{
		"plain":    {"42", 42, true},
		"zero":     {"0", 0, true},
		"negative": {"-7", -7, true},
		"empty":    {"", 0, false},
		"alpha":    {"12a", 0, false},
		"lonedash": {"-", 0, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := atoi(c.in)
			assert.Equal(t, c.ok, ok)
			if c.ok {
				assert.Equal(t, c.want, got)
			}
		})
	}
}
