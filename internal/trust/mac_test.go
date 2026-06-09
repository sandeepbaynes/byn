package trust

import (
	"bytes"
	"encoding/json"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestMACPreimage_Unambiguous(t *testing.T) {
	// Length-prefixing must keep field boundaries unambiguous: (a, bc) and
	// (ab, c) must not collide.
	if bytes.Equal(macPreimage("d", "a", "bc"), macPreimage("d", "ab", "c")) {
		t.Fatal("ambiguous field boundary — length prefix not working")
	}
	// The domain is bound in too.
	if bytes.Equal(macPreimage("d1", "p", "h"), macPreimage("d2", "p", "h")) {
		t.Fatal("domain not bound into the preimage")
	}
}

func TestComputeMAC_DeterministicAndSensitive(t *testing.T) {
	k1, k2 := key(1), key(2)
	base := computeMAC(k1, fpMACDomain, "/p/.byn", "abc")
	if base != computeMAC(k1, fpMACDomain, "/p/.byn", "abc") {
		t.Fatal("computeMAC is not deterministic")
	}
	for name, alt := range map[string]string{
		"different key":    computeMAC(k2, fpMACDomain, "/p/.byn", "abc"),
		"different domain": computeMAC(k1, vkMACDomain, "/p/.byn", "abc"),
		"different path":   computeMAC(k1, fpMACDomain, "/other/.byn", "abc"),
		"different hash":   computeMAC(k1, fpMACDomain, "/p/.byn", "abd"),
	} {
		if alt == base {
			t.Fatalf("MAC collision on %s", name)
		}
	}
}

func TestRecordMACs_RoundtripAndTamper(t *testing.T) {
	fpKey, vkKey := key(0xAA), key(0xBB)
	r := Record{Path: "/proj/.byn", SHA256: "deadbeef"}
	r.SetMACs(fpKey, vkKey)

	if !r.VerifyFPMAC(fpKey) || !r.VerifyVKMAC(vkKey) {
		t.Fatal("freshly minted MACs should verify")
	}
	if r.VerifyFPMAC(vkKey) || r.VerifyVKMAC(fpKey) {
		t.Fatal("a MAC verified under the wrong key")
	}

	// Your exact attack: a record minted under machine B's fingerprint key must
	// not verify on machine A.
	if r.VerifyFPMAC(key(0xCC)) {
		t.Fatal("record minted on another machine verified here")
	}

	// Tampering path or content-hash after minting invalidates both MACs.
	rp := r
	rp.Path = "/evil/.byn"
	if rp.VerifyFPMAC(fpKey) || rp.VerifyVKMAC(vkKey) {
		t.Fatal("tampered path still verified")
	}
	rh := r
	rh.SHA256 = "feedface"
	if rh.VerifyFPMAC(fpKey) || rh.VerifyVKMAC(vkKey) {
		t.Fatal("tampered content hash still verified")
	}
}

func TestRecordMACs_MissingAndEmptyKey(t *testing.T) {
	fpKey := key(1)
	r := Record{Path: "/p/.byn", SHA256: "abc"} // no MACs stamped

	// Pre-hardening / missing MAC is invalid — forces re-trust.
	if r.VerifyFPMAC(fpKey) || r.VerifyVKMAC(fpKey) {
		t.Fatal("missing MAC must be invalid")
	}

	r.SetMACs(fpKey, nil) // only the machine layer
	if !r.VerifyFPMAC(fpKey) {
		t.Fatal("fp MAC should be set and valid")
	}
	if r.VKMAC != "" {
		t.Fatal("nil vkKey should skip the vault-key layer")
	}
	if r.VerifyFPMAC(nil) || r.VerifyFPMAC([]byte{}) {
		t.Fatal("an empty key must never verify")
	}
}

func TestRecordMACs_DomainSeparation(t *testing.T) {
	k := key(7)
	r := Record{Path: "/p/.byn", SHA256: "abc"}
	r.SetMACs(k, k) // same key both layers; domains must still keep them distinct
	if r.FPMAC == r.VKMAC {
		t.Fatal("fp and vk MACs collide under one key — domain separation missing")
	}
	// Replaying the fp tag in the vk slot must not pass vk verification.
	forged := r
	forged.VKMAC = r.FPMAC
	if forged.VerifyVKMAC(k) {
		t.Fatal("fp MAC accepted as a vk MAC (cross-layer replay)")
	}
}

func TestRecord_JSONRoundtrip(t *testing.T) {
	fpKey, vkKey := key(1), key(2)
	r := Record{Path: "/p/.byn", SHA256: "abc", Vault: "work"}
	r.SetMACs(fpKey, vkKey)

	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got Record
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got != r {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", got, r)
	}
	if !got.VerifyFPMAC(fpKey) || !got.VerifyVKMAC(vkKey) {
		t.Fatal("MACs should survive a JSON roundtrip")
	}

	// A pre-hardening record (no MAC fields on disk) decodes to empty MACs and
	// must not verify.
	var old Record
	if err := json.Unmarshal([]byte(`{"path":"/p/.byn","sha256":"abc"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.FPMAC != "" || old.VKMAC != "" {
		t.Fatal("pre-hardening record should have empty MACs")
	}
	if old.VerifyFPMAC(fpKey) {
		t.Fatal("pre-hardening record must not verify (re-trust required)")
	}
}
