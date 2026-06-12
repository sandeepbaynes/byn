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

func TestParseActionsInExec(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"A\"]\nactions = [\"pnpm run start\", \"make test\"]\n"))
	require.NoError(t, err)
	assert.Equal(t, EnvList{"A"}, f.Exec.Env)
	assert.Equal(t, EnvList{"pnpm run start", "make test"}, f.Exec.Actions)
	assert.False(t, f.ActionsAllowAll())
}

func TestParseActionsBareStringWildcard(t *testing.T) {
	f, err := Parse([]byte("[exec]\nactions = \"*\"\n"))
	require.NoError(t, err)
	assert.Equal(t, EnvList{"*"}, f.Exec.Actions)
	assert.True(t, f.ActionsAllowAll())
}

func TestParseActionsListWildcard(t *testing.T) {
	f, err := Parse([]byte("[exec]\nactions = [\"*\"]\n"))
	require.NoError(t, err)
	assert.True(t, f.ActionsAllowAll())
}

func TestParseAbsentActions(t *testing.T) {
	f, err := Parse([]byte("[exec]\nenv = [\"A\"]\n"))
	require.NoError(t, err)
	assert.Nil(t, f.Exec.Actions)
	assert.False(t, f.ActionsAllowAll())
}

func TestParseAuthPolicy(t *testing.T) {
	f, err := Parse([]byte("[auth]\nget = \"always\"\ndelete = \"none\"\nexec = \"trusted\"\n"))
	require.NoError(t, err)
	assert.NotNil(t, f.Auth)
	assert.Equal(t, "always", f.Auth["get"])
	assert.Equal(t, "none", f.Auth["delete"])
	assert.Equal(t, "trusted", f.Auth["exec"])
	assert.NoError(t, f.ValidateAuth())
}

func TestValidateAuthUnknownKey(t *testing.T) {
	f, err := Parse([]byte("[auth]\nfoo = \"always\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[auth]")
	assert.Contains(t, err.Error(), "foo")
	assert.Contains(t, err.Error(), "unknown key")
	assert.Contains(t, err.Error(), "get, update, delete, exec")
}

func TestValidateAuthBadValue(t *testing.T) {
	f, err := Parse([]byte("[auth]\nget = \"maybe\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[auth]")
	assert.Contains(t, err.Error(), "get")
	assert.Contains(t, err.Error(), "maybe")
	assert.Contains(t, err.Error(), "invalid value")
	assert.Contains(t, err.Error(), "always, none")
}

func TestValidateAuthTrustedOnlyForExec(t *testing.T) {
	f, err := Parse([]byte("[auth]\nget = \"trusted\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[auth]")
	assert.Contains(t, err.Error(), "get")
	assert.Contains(t, err.Error(), "trusted")
	assert.Contains(t, err.Error(), "invalid value")
}

func TestValidateAuthAbsentReturnsNil(t *testing.T) {
	f, err := Parse([]byte("[scope]\nproject = \"p\"\n"))
	require.NoError(t, err)
	assert.Nil(t, f.Auth)
	assert.NoError(t, f.ValidateAuth())
}

func TestParseUnknownKeyInExecFails(t *testing.T) {
	_, err := Parse([]byte("[exec]\nbogus = 1\n"))
	require.Error(t, err)
}

func TestValidateAuthCaseSensitive(t *testing.T) {
	f, err := Parse([]byte("[auth]\nget = \"Always\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[auth]")
	assert.Contains(t, err.Error(), "get")
	assert.Contains(t, err.Error(), "Always")
	assert.Contains(t, err.Error(), "invalid value")
}

func TestValidateAuthEmptyValue(t *testing.T) {
	f, err := Parse([]byte("[auth]\nget = \"\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "[auth]")
	assert.Contains(t, err.Error(), "get")
	assert.Contains(t, err.Error(), "invalid value")
}

func TestValidateAuthValidUpdateValue(t *testing.T) {
	f, err := Parse([]byte("[auth]\nupdate = \"always\"\n"))
	require.NoError(t, err)
	err = f.ValidateAuth()
	require.NoError(t, err)
}

func TestValidateAuthDeterministic(t *testing.T) {
	toml := []byte("[auth]\nfoo = \"x\"\nget = \"bad\"\n")
	f1, err := Parse(toml)
	require.NoError(t, err)
	err1 := f1.ValidateAuth()

	f2, err := Parse(toml)
	require.NoError(t, err)
	err2 := f2.ValidateAuth()

	require.Error(t, err1)
	require.Error(t, err2)
	assert.Equal(t, err1.Error(), err2.Error())
}

func TestValidateAuthDuplicateKeyParseError(t *testing.T) {
	// go-toml v2 should reject duplicate keys at parse time
	_, err := Parse([]byte("[auth]\nget = \"always\"\nget = \"none\"\n"))
	require.Error(t, err)
}
