package ipc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecFetchOpRegistered(t *testing.T) {
	assert.Contains(t, AllOps, OpExecFetch)
}

func TestExecFetchRoundTrip(t *testing.T) {
	req := ExecFetchReq{Path: "/p/.byn", Scope: Scope{Vault: "v"}, Command: "pnpm run start"}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got ExecFetchReq
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, req, got)
}

func TestExecFetchWireStringsPinned(t *testing.T) {
	// Ops appear in every frame and error codes must never change
	// meaning — pin the literals so a constant edit can't slip through.
	assert.Equal(t, Op("exec.fetch"), OpExecFetch)
	assert.Equal(t, ErrCode("trust_denied"), CodeTrustDenied)
	assert.Equal(t, ErrCode("auth_required"), CodeAuthRequired)
}

func TestExecFetchRespBinaryValueRoundTrip(t *testing.T) {
	resp := ExecFetchResp{Values: []ExecFetchValue{{Name: "K", Value: []byte{0x00, 0xff, 0x10, 0x80}}}, Wildcard: true}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	var got ExecFetchResp
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, resp, got)
}

func TestAuthFieldsOmittedWhenEmpty(t *testing.T) {
	// Version-skew contract: a request without per-action auth must
	// marshal to the same wire bytes as before the fields existed.
	t.Run("GetReq", func(t *testing.T) {
		b, err := json.Marshal(GetReq{Name: "X"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("RenameReq", func(t *testing.T) {
		b, err := json.Marshal(RenameReq{OldName: "A", NewName: "B"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("EnvClearReq", func(t *testing.T) {
		b, err := json.Marshal(EnvClearReq{})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("ProjectDeleteReq", func(t *testing.T) {
		b, err := json.Marshal(ProjectDeleteReq{Name: "svc"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("EnvDeleteReq", func(t *testing.T) {
		b, err := json.Marshal(EnvDeleteReq{Project: "default", Name: "stg"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("VaultDeleteReq", func(t *testing.T) {
		b, err := json.Marshal(VaultDeleteReq{Name: "acme"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("VaultRenameReq", func(t *testing.T) {
		b, err := json.Marshal(VaultRenameReq{OldName: "acme", NewName: "brand"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
}
