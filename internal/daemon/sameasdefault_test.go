package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestList_SameAsDefault runs the real list path end to end: a value in a
// non-default env that repeats default's is reported as in_default with
// same_as_default true, one that differs as false, and after an edit the
// answer follows the new value.
func TestList_SameAsDefault(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("testpass")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := c.Call(ipc.OpEnvCreate, ipc.EnvCreateReq{Project: "default", Name: "staging"}, &ipc.EnvCreateResp{}); err != nil {
		t.Fatalf("env create: %v", err)
	}
	staging := ipc.Scope{Env: "staging"}
	put := func(sc ipc.Scope, name, val string) {
		t.Helper()
		if err := c.Call(ipc.OpPut, ipc.PutReq{Scope: sc, Name: name, Value: []byte(val), Password: pw}, &ipc.PutResp{}); err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
	}
	put(ipc.Scope{}, "SAME", "shared-value")
	put(staging, "SAME", "shared-value")
	put(ipc.Scope{}, "DIFF", "aaaa")
	put(staging, "DIFF", "bbbb")
	put(ipc.Scope{}, "INHERITED", "x")
	put(staging, "ONLY_HERE", "y")

	list := func() map[string]ipc.SecretMeta {
		t.Helper()
		var lr ipc.ListResp
		if err := c.Call(ipc.OpList, ipc.ListReq{Scope: staging}, &lr); err != nil {
			t.Fatalf("list: %v", err)
		}
		m := map[string]ipc.SecretMeta{}
		for _, s := range lr.Secrets {
			m[s.Name] = s
		}
		return m
	}
	check := func(m map[string]ipc.SecretMeta, name string, inDefault bool, same *bool) {
		t.Helper()
		s, ok := m[name]
		if !ok {
			t.Fatalf("%s missing from list", name)
		}
		if s.InDefault != inDefault {
			t.Errorf("%s.InDefault = %v, want %v", name, s.InDefault, inDefault)
		}
		switch {
		case same == nil && s.SameAsDefault != nil:
			t.Errorf("%s.SameAsDefault = %v, want nil", name, *s.SameAsDefault)
		case same != nil && s.SameAsDefault == nil:
			t.Errorf("%s.SameAsDefault = nil, want %v", name, *same)
		case same != nil && *s.SameAsDefault != *same:
			t.Errorf("%s.SameAsDefault = %v, want %v", name, *s.SameAsDefault, *same)
		}
	}
	yes, no := true, false
	m := list()
	check(m, "SAME", true, &yes)
	check(m, "DIFF", true, &no)
	check(m, "INHERITED", false, nil)
	check(m, "ONLY_HERE", false, nil)

	// A manual edit is compared afresh: typing default's value back makes
	// the row "same", and changing it again makes it an override.
	put(staging, "DIFF", "aaaa")
	check(list(), "DIFF", true, &yes)
	put(staging, "SAME", "shared-value-2")
	check(list(), "SAME", true, &no)

	// Locked: same-sized pairs cannot be decided and are left nil; a
	// different size is still reported as differing.
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}
	m = list()
	check(m, "DIFF", true, nil)
	check(m, "SAME", true, &no)
}
