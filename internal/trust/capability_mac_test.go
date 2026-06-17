package trust

import "testing"

// TestRecordMACs_BindExecCapability: the sealed capability is MAC-bound on a v2
// record, so add/remove/swap of the blob all fail verification.
func TestRecordMACs_BindExecCapability(t *testing.T) {
	fpKey, vkKey := key(0xAA), key(0xBB)
	// v2 (Snapshot set ⇒ IsV2) carrying a capability blob.
	r := Record{Path: "/p/.byn", SHA256: "abc", Snapshot: "[scope]\n", ExecCapability: []byte("sealed-cap-blob")}
	r.SetMACs(fpKey, vkKey)
	if !r.VerifyFPMAC(fpKey) || !r.VerifyVKMAC(vkKey) {
		t.Fatal("capability record should verify with the right keys")
	}

	swap := r
	swap.ExecCapability = []byte("different-blob")
	if swap.VerifyFPMAC(fpKey) || swap.VerifyVKMAC(vkKey) {
		t.Fatal("swapping the capability must invalidate the MACs")
	}

	rm := r
	rm.ExecCapability = nil
	if rm.VerifyFPMAC(fpKey) || rm.VerifyVKMAC(vkKey) {
		t.Fatal("removing the capability must invalidate the MACs")
	}
}

// TestRecordMACs_NoCapabilityBackCompat: a v2 record with NO capability verifies
// (the conditional-inclusion keeps the preimage identical to before this field
// existed), and injecting a capability into a record stamped without one fails.
func TestRecordMACs_NoCapabilityBackCompat(t *testing.T) {
	fpKey := key(0xCD)
	r := Record{Path: "/p/.byn", SHA256: "abc", Snapshot: "x"} // v2, no capability
	r.SetMACs(fpKey, nil)
	if !r.VerifyFPMAC(fpKey) {
		t.Fatal("no-capability v2 record must verify")
	}
	add := r
	add.ExecCapability = []byte("injected")
	if add.VerifyFPMAC(fpKey) {
		t.Fatal("adding a capability to a record stamped without one must fail")
	}
}
