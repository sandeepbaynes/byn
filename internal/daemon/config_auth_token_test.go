package daemon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigAuthTokens_MintAndConsumeOnce(t *testing.T) {
	c := newConfigAuthTokens()
	now := time.Unix(1_700_000_000, 0)

	tok, err := c.mint(now)
	require.NoError(t, err)
	assert.NotEmpty(t, tok)

	// Valid + unexpired → consumed once.
	assert.True(t, c.consume(tok, now.Add(time.Second)))
	// Single-use: the second consume fails.
	assert.False(t, c.consume(tok, now.Add(time.Second)), "token must be single-use")
}

func TestConfigAuthTokens_Expired(t *testing.T) {
	c := newConfigAuthTokens()
	now := time.Unix(1_700_000_000, 0)
	tok, err := c.mint(now)
	require.NoError(t, err)
	// Past the 60s TTL → rejected (and removed).
	assert.False(t, c.consume(tok, now.Add(61*time.Second)))
}

func TestConfigAuthTokens_UnknownAndEmpty(t *testing.T) {
	c := newConfigAuthTokens()
	now := time.Unix(1_700_000_000, 0)
	assert.False(t, c.consume("", now))
	assert.False(t, c.consume("deadbeef", now))
}

func TestConfigAuthTokens_DistinctTokens(t *testing.T) {
	c := newConfigAuthTokens()
	now := time.Unix(1_700_000_000, 0)
	a, err := c.mint(now)
	require.NoError(t, err)
	b, err := c.mint(now)
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "each mint must be unique")
}
