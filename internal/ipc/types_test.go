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

// TestExecFetchReqArgvRoundTrip verifies that Argv round-trips correctly and
// that an ExecFetchReq without Argv marshals without the "argv" key (omitempty
// contract — old CLIs that don't send Argv must not break the wire format).
func TestExecFetchReqArgvRoundTrip(t *testing.T) {
	t.Run("with Argv", func(t *testing.T) {
		req := ExecFetchReq{Path: "/p/.byn", Argv: []string{"pnpm", "run", "start"}}
		b, err := json.Marshal(req)
		require.NoError(t, err)
		assert.Contains(t, string(b), "argv", "argv must be present when non-empty")

		var got ExecFetchReq
		require.NoError(t, json.Unmarshal(b, &got))
		assert.Equal(t, req.Argv, got.Argv)
	})

	t.Run("without Argv omitted", func(t *testing.T) {
		req := ExecFetchReq{Path: "/p/.byn", Command: "pnpm run start"}
		b, err := json.Marshal(req)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "argv", "argv must be absent when nil (omitempty)")
	})
}

// TestExecFetchRespActionsWildcardOmitEmpty verifies that ActionsWildcard=false
// is omitted from the wire (omitempty) so old clients receiving a response from
// a new daemon are not surprised by the new field.
func TestExecFetchRespActionsWildcardOmitEmpty(t *testing.T) {
	t.Run("false is omitted", func(t *testing.T) {
		resp := ExecFetchResp{Values: []ExecFetchValue{{Name: "K", Value: []byte("v")}}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.NotContains(t, string(b), "actions_wildcard",
			"ActionsWildcard=false must be absent (omitempty)")
	})

	t.Run("true is present and round-trips", func(t *testing.T) {
		resp := ExecFetchResp{ActionsWildcard: true}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.Contains(t, string(b), "actions_wildcard",
			"ActionsWildcard=true must be present")

		var got ExecFetchResp
		require.NoError(t, json.Unmarshal(b, &got))
		assert.True(t, got.ActionsWildcard)
	})
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
	t.Run("TrustGrantReq", func(t *testing.T) {
		b, err := json.Marshal(TrustGrantReq{Path: "/tmp/.byn"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("TrustGrantBulkReq", func(t *testing.T) {
		b, err := json.Marshal(TrustGrantBulkReq{Paths: []string{"/tmp/.byn"}})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
	})
	t.Run("ExecFetchReq", func(t *testing.T) {
		// An ExecFetchReq with no password/presence_token/argv must omit those
		// fields — old-version compatibility (version-skew contract).
		b, err := json.Marshal(ExecFetchReq{Path: "/p/.byn", Command: "cmd"})
		require.NoError(t, err)
		assert.NotContains(t, string(b), "password")
		assert.NotContains(t, string(b), "presence_token")
		assert.NotContains(t, string(b), "argv")
	})
}
