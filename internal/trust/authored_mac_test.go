package trust

import "testing"

// A self-authored grant is a free widening, so it has to be as hard to forge as
// the policy tables next to it. These check that every way of editing the list
// breaks the MAC — including the two directions the "omit when empty" encoding
// makes easy to get wrong.

func authoredTestRecord() Record {
	return Record{
		Path:          "/p/.byn",
		SHA256:        "abc",
		Vault:         "default",
		MTimeUnixNano: 1234,
		Snapshot:      "[scope]\n",
	}
}

func TestSelfAuthoredIsMACBound(t *testing.T) {
	fp, vk := []byte("fp-key-32-bytes-len-not-checked!"), []byte("vk-key-32-bytes-len-not-checked!")

	base := authoredTestRecord()
	base.SelfAuthored = []AuthoredGrant{{Name: "API_TOKEN", OriginPID: 42, OriginStart: 7, AtUnixNano: 99}}
	base.SetMACs(fp, vk)
	if !base.VerifyFPMAC(fp) || !base.VerifyVKMAC(vk) {
		t.Fatal("a freshly stamped record must verify")
	}

	tampered := map[string]func(r *Record){
		"added an entry": func(r *Record) {
			r.SelfAuthored = append(r.SelfAuthored, AuthoredGrant{Name: "AWS_SECRET", OriginPID: 42, OriginStart: 7})
		},
		"renamed the variable":   func(r *Record) { r.SelfAuthored[0].Name = "AWS_SECRET" },
		"claimed another origin": func(r *Record) { r.SelfAuthored[0].OriginPID = 43 },
		"reused a recycled pid":  func(r *Record) { r.SelfAuthored[0].OriginStart = 8 },
		"cleared the list":       func(r *Record) { r.SelfAuthored = nil },
	}
	for name, tamper := range tampered {
		t.Run(name, func(t *testing.T) {
			r := base
			r.SelfAuthored = append([]AuthoredGrant(nil), base.SelfAuthored...)
			tamper(&r)
			if r.VerifyFPMAC(fp) {
				t.Errorf("fp-MAC still verified after %s", name)
			}
			if r.VerifyVKMAC(vk) {
				t.Errorf("vk-MAC still verified after %s", name)
			}
		})
	}
}

// Forging a list onto a record that had none must fail too: that is the exact
// move an attacker would make to grant themselves a variable, and the encoding
// deliberately omits the field when empty.
func TestSelfAuthoredCannotBeForgedOntoARecordWithNone(t *testing.T) {
	fp, vk := []byte("fp-key-32-bytes-len-not-checked!"), []byte("vk-key-32-bytes-len-not-checked!")

	r := authoredTestRecord()
	r.SetMACs(fp, vk)
	if !r.VerifyFPMAC(fp) || !r.VerifyVKMAC(vk) {
		t.Fatal("a record with no authored grants must verify")
	}
	r.SelfAuthored = []AuthoredGrant{{Name: "AWS_SECRET", OriginPID: 1, OriginStart: 1}}
	if r.VerifyFPMAC(fp) || r.VerifyVKMAC(vk) {
		t.Error("an authored grant was forged onto a record that had none")
	}
}

// Order must not matter: the same set written in a different order is the same
// grant, and must keep verifying.
func TestSelfAuthoredMACIsOrderIndependent(t *testing.T) {
	fp, vk := []byte("fp-key-32-bytes-len-not-checked!"), []byte("vk-key-32-bytes-len-not-checked!")

	r := authoredTestRecord()
	r.SelfAuthored = []AuthoredGrant{
		{Name: "A", OriginPID: 1, OriginStart: 2},
		{Name: "B", OriginPID: 3, OriginStart: 4},
	}
	r.SetMACs(fp, vk)

	r.SelfAuthored[0], r.SelfAuthored[1] = r.SelfAuthored[1], r.SelfAuthored[0]
	if !r.VerifyFPMAC(fp) || !r.VerifyVKMAC(vk) {
		t.Error("reordering the same grants must not break the MAC")
	}
}
