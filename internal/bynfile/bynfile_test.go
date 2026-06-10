package bynfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScopeAndExecEnvList(t *testing.T) {
	f, err := Parse([]byte("[scope]\nvault = \"acme\"\nproject = \"api\"\nenv = \"dev\"\n[exec]\nenv = [\"DB_URL\", \"API_KEY\"]\n"))
	require.NoError(t, err)
	assert.Equal(t, "acme", f.Scope.Vault)
	assert.Equal(t, "api", f.Scope.Project)
	assert.Equal(t, "dev", f.Scope.Env)
	assert.Equal(t, EnvList{"DB_URL", "API_KEY"}, f.Exec.Env)
	assert.False(t, f.AllowsAll())
}

func TestParseBareStringWildcard(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = \"*\"\n"))
	require.NoError(t, err)
	assert.Equal(t, EnvList{"*"}, f.Exec.Env)
	assert.True(t, f.AllowsAll())
}

func TestParseListWildcard(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"*\"]\n"))
	require.NoError(t, err)
	assert.True(t, f.AllowsAll())
}

func TestParseUnknownKeyFails(t *testing.T) {
	_, err := Parse([]byte("[scope]\nvault = \"a\"\nbogus = 1\n"))
	require.Error(t, err)
}

func TestParseEmptyExecEnv(t *testing.T) {
	f, err := Parse([]byte("[scope]\nproject = \"p\"\n"))
	require.NoError(t, err)
	assert.Empty(t, f.Exec.Env)
	assert.False(t, f.AllowsAll())
}
