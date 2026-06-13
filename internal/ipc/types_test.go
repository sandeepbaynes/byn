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

// TestExecSpawnOpRegistered verifies the exec.spawn op is registered + pinned.
func TestExecSpawnOpRegistered(t *testing.T) {
	assert.Contains(t, AllOps, OpExecSpawn)
	assert.Equal(t, Op("exec.spawn"), OpExecSpawn)
}

// TestExecSpawnReqRoundTrip verifies the embedded ExecFetchReq fields plus the
// spawn-only fields (BaseEnv, AbsTarget) round-trip through JSON intact.
func TestExecSpawnReqRoundTrip(t *testing.T) {
	req := ExecSpawnReq{
		ExecFetchReq: ExecFetchReq{
			Path:    "/p/.byn",
			Scope:   Scope{Vault: "v"},
			Command: "mytool run",
			Argv:    []string{"mytool", "run"},
			Alias:   "deploy",
		},
		BaseEnv:   []string{"PATH=/usr/bin", "TERM=xterm"},
		AbsTarget: "/usr/local/bin/mytool",
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got ExecSpawnReq
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, req, got)
	// The embedded fields must serialize at the top level (flattened), not nested.
	assert.Contains(t, string(b), `"path":"/p/.byn"`)
	assert.Contains(t, string(b), `"abs_target":"/usr/local/bin/mytool"`)
	assert.Contains(t, string(b), `"base_env":`)
}

// TestExecSpawnReqOmitEmpty verifies the spawn-only fields are omitted when
// unset (version-skew contract).
func TestExecSpawnReqOmitEmpty(t *testing.T) {
	b, err := json.Marshal(ExecSpawnReq{ExecFetchReq: ExecFetchReq{Path: "/p/.byn"}})
	require.NoError(t, err)
	assert.NotContains(t, string(b), "base_env")
	assert.NotContains(t, string(b), "abs_target")
}

// TestExecSpawnRespRoundTrip verifies the exit code round-trips.
func TestExecSpawnRespRoundTrip(t *testing.T) {
	resp := ExecSpawnResp{ExitCode: 42}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	var got ExecSpawnResp
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, resp, got)
}

// TestBynStudioOpsRegistered verifies that all new studio ops are in AllOps.
func TestBynStudioOpsRegistered(t *testing.T) {
	for _, op := range []Op{OpBynValidate, OpBynSimulate, OpBynRead, OpConfigGet, OpConfigSet} {
		found := false
		for _, a := range AllOps {
			if a == op {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("op %q not found in AllOps", op)
		}
	}
}

// TestBynStudioWireStringsPinned pins the literal op strings so a rename can't
// slip through without a test failure.
func TestBynStudioWireStringsPinned(t *testing.T) {
	assert.Equal(t, Op("byn.validate"), OpBynValidate)
	assert.Equal(t, Op("byn.simulate"), OpBynSimulate)
	assert.Equal(t, Op("byn.read"), OpBynRead)
	assert.Equal(t, Op("config.get"), OpConfigGet)
	assert.Equal(t, Op("config.set"), OpConfigSet)
}

// TestBynValidateRoundTrip verifies BynValidateReq/Resp round-trip.
func TestBynValidateRoundTrip(t *testing.T) {
	req := BynValidateReq{Content: []byte("[scope]\n")}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got BynValidateReq
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, req, got)
}

// TestBynValidateRespOmitEmpty verifies that empty Errors/Warnings are omitted.
func TestBynValidateRespOmitEmpty(t *testing.T) {
	resp := BynValidateResp{}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "errors")
	assert.NotContains(t, string(b), "warnings")
}

// TestBynSimulateRoundTrip verifies BynSimulateReq/Resp round-trip.
func TestBynSimulateRoundTrip(t *testing.T) {
	req := BynSimulateReq{Content: []byte("[exec]\n"), CommandLine: "aws s3 ls"}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got BynSimulateReq
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, req, got)
}

// TestBynReadRoundTrip verifies BynReadReq/Resp round-trip.
func TestBynReadRoundTrip(t *testing.T) {
	req := BynReadReq{Path: "/tmp/.byn"}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	var got BynReadReq
	require.NoError(t, json.Unmarshal(b, &got))
	assert.Equal(t, req, got)
}

// TestConfigGetRespContentOmitEmpty verifies Content is omitted when empty.
func TestConfigGetRespContentOmitEmpty(t *testing.T) {
	resp := ConfigGetResp{Path: "/tmp/config"}
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "content", "content must be absent when empty (omitempty)")
}

// TestBynWriteReqContentOmitEmpty verifies that Content is omitted when not set.
func TestBynWriteReqContentOmitEmpty(t *testing.T) {
	req := BynWriteReq{Dir: "/tmp"}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "content", "Content must be absent when nil (omitempty)")
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
