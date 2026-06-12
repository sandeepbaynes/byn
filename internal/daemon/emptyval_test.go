package daemon

import (
	"testing"

	"github.com/sandeepbaynes/byn/internal/ipc"
)

// TestListEmpty_EmptyFieldPopulatedWhenUnlocked verifies that SecretMeta.Empty
// is non-nil and true for an entry with an empty value when the vault is
// unlocked, and nil (omitted) when the vault is locked.
func TestListEmpty_EmptyFieldPopulatedWhenUnlocked(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("testpass")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Put an entry with an empty value.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "EMPTY_VAR", Value: []byte{}}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put empty: %v", err)
	}
	// Put an entry with a non-empty value.
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "NON_EMPTY", Value: []byte("hello")}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put non-empty: %v", err)
	}

	// List while unlocked: Empty must be populated.
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("list unlocked: %v", err)
	}
	m := make(map[string]ipc.SecretMeta)
	for _, s := range lr.Secrets {
		m[s.Name] = s
	}
	emptyMeta, ok := m["EMPTY_VAR"]
	if !ok {
		t.Fatal("EMPTY_VAR not in list")
	}
	if emptyMeta.Empty == nil {
		t.Error("EMPTY_VAR: Empty is nil when vault is unlocked, want non-nil")
	} else if !*emptyMeta.Empty {
		t.Error("EMPTY_VAR: Empty is false, want true")
	}
	nonEmptyMeta, ok := m["NON_EMPTY"]
	if !ok {
		t.Fatal("NON_EMPTY not in list")
	}
	if nonEmptyMeta.Empty == nil {
		t.Error("NON_EMPTY: Empty is nil when vault is unlocked, want non-nil")
	} else if *nonEmptyMeta.Empty {
		t.Error("NON_EMPTY: Empty is true, want false")
	}
}

// TestListEmpty_EmptyFieldOmittedWhenLocked verifies that SecretMeta.Empty
// is nil (omitted) when the vault is locked. Listing is allowed while locked
// (names only, no values); Empty must not be computed.
func TestListEmpty_EmptyFieldOmittedWhenLocked(t *testing.T) {
	_, c := startTestDaemon(t)
	pw := []byte("testpass")
	if err := c.Call(ipc.OpVaultInit, ipc.VaultInitReq{Password: pw}, &ipc.VaultInitResp{}); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Unlock briefly to store a value, then lock again.
	if err := c.Call(ipc.OpVaultUnlock, ipc.VaultUnlockReq{Password: pw}, &ipc.VaultUnlockResp{}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := c.Call(ipc.OpPut, ipc.PutReq{Name: "K", Value: []byte{}}, &ipc.PutResp{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := c.Call(ipc.OpVaultLock, ipc.VaultLockReq{}, &ipc.VaultLockResp{}); err != nil {
		t.Fatalf("lock: %v", err)
	}

	// List while locked: Empty must be nil.
	var lr ipc.ListResp
	if err := c.Call(ipc.OpList, ipc.ListReq{}, &lr); err != nil {
		t.Fatalf("list locked: %v", err)
	}
	for _, s := range lr.Secrets {
		if s.Empty != nil {
			t.Errorf("entry %q: Empty is non-nil while vault is locked, want nil", s.Name)
		}
	}
}
