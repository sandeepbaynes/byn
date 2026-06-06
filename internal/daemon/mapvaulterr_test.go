package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

func TestMapVaultErr_AllCases(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want ipc.ErrCode
	}{
		{"locked", vault.ErrLocked, ipc.CodeLocked},
		{"not found", vault.ErrNotFound, ipc.CodeNotFound},
		{"exists", vault.ErrExists, ipc.CodeAlreadyExists},
		{"bad name", vault.ErrBadName, ipc.CodeBadName},
		{"project not found", vault.ErrProjectNotFound, ipc.CodeProjectNotFound},
		{"project exists", vault.ErrProjectExists, ipc.CodeProjectExists},
		{"bad project name", vault.ErrBadProjectName, ipc.CodeBadName},
		{"env not found", vault.ErrEnvNotFound, ipc.CodeEnvNotFound},
		{"env exists", vault.ErrEnvExists, ipc.CodeEnvExists},
		{"env protected", vault.ErrEnvProtected, ipc.CodeEnvProtected},
		{"bad env name", vault.ErrBadEnvName, ipc.CodeBadName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := mapVaultErr("id1", tc.in)
			if env.Err == nil {
				t.Fatal("nil err")
			}
			if env.Err.Code != tc.want {
				t.Fatalf("Code=%v, want %v", env.Err.Code, tc.want)
			}
		})
	}
}
