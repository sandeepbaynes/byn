package trust

// v2_test.go — tests for the trust-record v2 fields (mtime, snapshot,
// MAC-bound policy, scope). All tests in this file use the package-internal
// style (no testify) matching the rest of the trust package.

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"
)

// ---- helpers ----------------------------------------------------------------

// makeV2Rec returns a fully-populated v2 record with MACs stamped.
func makeV2Rec(path, sha string, fpKey, vkKey []byte) Record {
	r := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: 1_700_000_000_123_456_789,
		Snapshot:      "[scope]\nproject = \"svc\"\n",
		Actions:       []string{"make test", "pnpm run dev"},
		Auth:          map[string]string{"get": "password", "exec": "password"},
		Aliases:       map[string]string{"test": "npm test", "scrape": "npm run scrape"},
		ScopeVault:    "work",
		ScopeProject:  "svc",
		ScopeEnv:      "prod",
	}
	r.SetMACs(fpKey, vkKey)
	return r
}

// ---- v2 round-trip trusted --------------------------------------------------

// TestV2_RoundTrip_Trusted verifies that a v2 record grants and verifies as
// trusted end-to-end: store → retrieve → Verify.
func TestV2_RoundTrip_Trusted(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(0x01), key(0x02)
	const path, sha = "/proj/.byn", "abc123"
	const mtime int64 = 1_700_000_000_123_456_789

	rec := makeV2Rec(path, sha, fpKey, vkKey)
	if _, err := Put(dir, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	st, vkChecked, _, err := Verify(dir, path, sha, mtime, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st != VerifyTrusted {
		t.Fatalf("status = %s, want trusted", st)
	}
	if !vkChecked {
		t.Error("vkKey provided → vk-MAC should have been checked")
	}
}

// ---- mtime drift with same hash → changed -----------------------------------

// TestV2_MTimeDrift_SameHash verifies that touching a file (same content,
// different mtime) yields VerifyChanged for a v2 record.
func TestV2_MTimeDrift_SameHash(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(0x01), key(0x02)
	const path, sha = "/proj/.byn", "abc123"
	const grantedMTime int64 = 1_700_000_000_000_000_000

	rec := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: grantedMTime,
		Snapshot:      "snap",
	}
	rec.SetMACs(fpKey, vkKey)
	if _, err := Put(dir, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Same hash, different mtime (file was touched).
	st, _, _, err := Verify(dir, path, sha, grantedMTime+1, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st != VerifyChanged {
		t.Fatalf("mtime drift: %s, want changed", st)
	}

	// Same hash AND same mtime → trusted.
	st2, _, _, err := Verify(dir, path, sha, grantedMTime, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify same mtime: %v", err)
	}
	if st2 != VerifyTrusted {
		t.Fatalf("same mtime: %s, want trusted", st2)
	}
}

// ---- v1 record (authentic v1 MACs) → stale ----------------------------------

// TestV1_AuthenticMACs_Stale verifies that a hand-built v1 record (no v2
// fields, v1-domain MACs) is classified stale — authentic but pre-upgrade.
func TestV1_AuthenticMACs_Stale(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(0xAA), key(0xBB)
	const path, sha = "/proj/.byn", "abc123"

	// Manually build a v1 record: no MTimeUnixNano, no Snapshot ⇒ IsV2=false.
	// SetMACs will stamp v1-domain MACs.
	rec := Record{Path: path, SHA256: sha, Vault: "default"}
	rec.SetMACs(fpKey, vkKey)
	if rec.IsV2() {
		t.Fatal("should be v1: no v2 fields set")
	}
	if _, err := Put(dir, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Any mtime is passed because v1 records ignore it.
	st, _, _, err := Verify(dir, path, sha, 9999, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st != VerifyStale {
		t.Fatalf("v1 authentic: %s, want stale", st)
	}
}

// ---- v1 record with forged field → tampered ---------------------------------

// TestV1_ForgedField_Tampered verifies that a v1 record with an invalid FPMAC
// (field tampered after minting) yields VerifyTampered, not stale.
func TestV1_ForgedField_Tampered(t *testing.T) {
	dir := t.TempDir()
	fpKey, vkKey := key(0xAA), key(0xBB)
	const path, sha = "/proj/.byn", "abc123"

	rec := Record{Path: path, SHA256: sha}
	rec.SetMACs(fpKey, vkKey)
	// Corrupt the FPMAC to simulate a tampered field.
	rec.FPMAC = "00deadbeef00"
	if _, err := Put(dir, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	st, _, _, err := Verify(dir, path, sha, 0, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st != VerifyTampered {
		t.Fatalf("v1 forged FPMAC: %s, want tampered", st)
	}
}

// ---- per-field post-MAC-edit → tampered (one test per field) ----------------

// editAndVerify stamps a v2 record, lets the caller mutate it, stores it, and
// checks that Verify returns VerifyTampered (not trusted).
//
// We pass the record's (post-edit) MTimeUnixNano as currentMTime so the
// mtime-equality check is not what rejects the record — it must be the MAC
// check that fires. For the MTime mutation test we pass the *modified* value
// so the check reaches the MAC layer.
func editAndVerify(t *testing.T, edit func(*Record)) {
	t.Helper()
	dir := t.TempDir()
	fpKey, vkKey := key(0x10), key(0x20)
	const path, sha = "/proj/.byn", "abc123"

	rec := makeV2Rec(path, sha, fpKey, vkKey)
	// Mutate AFTER MACs are stamped.
	edit(&rec)
	if _, err := Put(dir, rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Pass the stored record's mtime so the mtime equality check does NOT
	// fire; the MAC check must be what catches the tamper.
	st, _, _, err := Verify(dir, path, sha, rec.MTimeUnixNano, fpKey, vkKey)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if st != VerifyTampered {
		t.Fatalf("status = %s, want tampered after field edit", st)
	}
}

func TestV2_PostMACEdit_MTime_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		// Change mtime after minting — the v2 preimage binds it.
		r.MTimeUnixNano = 999
	})
}

func TestV2_PostMACEdit_Snapshot_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.Snapshot = "[scope]\nevil = \"true\"\n"
	})
}

func TestV2_PostMACEdit_Action_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.Actions = append(r.Actions, "rm -rf /")
	})
}

func TestV2_PostMACEdit_Auth_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.Auth["exec"] = "none" // weaken the exec policy
	})
}

func TestV2_PostMACEdit_ScopeVault_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.ScopeVault = "evil"
	})
}

func TestV2_PostMACEdit_ScopeProject_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.ScopeProject = "evil"
	})
}

func TestV2_PostMACEdit_ScopeEnv_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.ScopeEnv = "evil"
	})
}

func TestV2_PostMACEdit_Vault_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		r.Vault = "other-vault"
	})
}

// ---- auth pair encoding collision regression --------------------------------

// TestV2_AuthPairEncoding_NoCollision is a regression test for the auth
// encoding fix: {"a":"b=c"} and {"a=b":"c"} must produce different preimages.
// Previously encoding was writeField(k+"="+v) which caused these to collide.
// The fix writes key and value as two separate length-prefixed fields.
func TestV2_AuthPairEncoding_NoCollision(t *testing.T) {
	const domain = "byn:trust-fp-mac:v2"
	const path, sha = "/proj/.byn", "abc123"
	const mtime int64 = 1_700_000_000_000_000_000

	// Construct Records directly (bypassing ValidateAuth) to exercise the
	// encoding with keys/values containing "=".
	r1 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: mtime,
		Auth:          map[string]string{"a": "b=c"},
	}
	r2 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: mtime,
		Auth:          map[string]string{"a=b": "c"},
	}

	p1 := macPreimageV2(domain, path, sha, &r1)
	p2 := macPreimageV2(domain, path, sha, &r2)
	if string(p1) == string(p2) {
		t.Fatal(`auth encoding collision: {"a":"b=c"} and {"a=b":"c"} produced the same preimage`)
	}

	// Also verify the MACs differ.
	fpKey := key(0x42)
	r1.SetMACs(fpKey, nil)
	r2.SetMACs(fpKey, nil)
	if r1.FPMAC == r2.FPMAC {
		t.Fatal(`MAC collision: {"a":"b=c"} and {"a=b":"c"} produced identical FPMACs`)
	}
}

// ---- preimage-uniqueness property test --------------------------------------

// TestV2_PreimageUniqueness generates 1000 random Record pairs that differ in
// exactly one v2 field and asserts they produce different preimages. This
// guards against encoding collisions (e.g. missing length prefixes, wrong
// count encoding).
func TestV2_PreimageUniqueness(t *testing.T) {
	const domain = "byn:trust-fp-mac:v2"
	const path = "/proj/.byn"
	const sha = "abc123"
	const iterations = 1000

	rng := rand.New(rand.NewSource(42)) //nolint:gosec // deterministic seed for reproducibility
	randStr := func(n int) string {
		const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, n)
		for i := range b {
			b[i] = charset[rng.Intn(len(charset))]
		}
		return string(b)
	}

	type mutator struct {
		name string
		fn   func(r *Record)
	}
	mutators := []mutator{
		{"mtime", func(r *Record) { r.MTimeUnixNano++ }},
		{"snapshot", func(r *Record) { r.Snapshot += "x" }},
		{"action_add", func(r *Record) { r.Actions = append(r.Actions, randStr(4)) }},
		{"action_edit", func(r *Record) {
			if len(r.Actions) == 0 {
				r.Actions = []string{randStr(4)}
			} else {
				r.Actions[0] += "x"
			}
		}},
		{"auth_edit", func(r *Record) {
			for k := range r.Auth {
				r.Auth[k] += "x"
				break
			}
		}},
		{"scope_vault", func(r *Record) { r.ScopeVault += "x" }},
		{"scope_project", func(r *Record) { r.ScopeProject += "x" }},
		{"scope_env", func(r *Record) { r.ScopeEnv += "x" }},
		{"alias_add", func(r *Record) {
			if r.Aliases == nil {
				r.Aliases = map[string]string{}
			}
			r.Aliases[randStr(4)] = randStr(4)
		}},
		{"alias_edit", func(r *Record) {
			for k := range r.Aliases {
				r.Aliases[k] += "x"
				break
			}
			if len(r.Aliases) == 0 {
				r.Aliases = map[string]string{randStr(3): randStr(4)}
			}
		}},
	}

	for i := 0; i < iterations; i++ {
		mut := mutators[rng.Intn(len(mutators))]
		base := Record{
			Path:          path,
			SHA256:        sha,
			MTimeUnixNano: rng.Int63(),
			Snapshot:      randStr(8),
			Actions:       []string{randStr(4), randStr(4)},
			Auth:          map[string]string{randStr(3): randStr(4)},
			Aliases:       map[string]string{randStr(3): randStr(4)},
			ScopeVault:    randStr(4),
			ScopeProject:  randStr(4),
			ScopeEnv:      randStr(4),
		}
		modified := base
		// Deep-copy slices/maps so mutation doesn't alias.
		modified.Actions = append([]string(nil), base.Actions...)
		modified.Auth = make(map[string]string, len(base.Auth))
		for k, v := range base.Auth {
			modified.Auth[k] = v
		}
		modified.Aliases = make(map[string]string, len(base.Aliases))
		for k, v := range base.Aliases {
			modified.Aliases[k] = v
		}
		mut.fn(&modified)

		p1 := macPreimageV2(domain, path, sha, &base)
		p2 := macPreimageV2(domain, path, sha, &modified)
		if string(p1) == string(p2) {
			t.Fatalf("iteration %d (%s): identical preimages for differing records", i, mut.name)
		}
	}
}

// ---- Set/Verify symmetry trap -----------------------------------------------

// TestV2_SetVerifySymmetry is the invariant pin: SetMACs and Verify*MAC must
// choose the SAME preimage version (decided by IsV2). Asymmetry → records
// self-classify as tampered.
func TestV2_SetVerifySymmetry(t *testing.T) {
	fpKey, vkKey := key(0xAA), key(0xBB)

	// v1 record: SetMACs stamps v1-domain MACs; VerifyFPMAC/VerifyVKMAC must
	// check v1-domain too (not v2).
	v1 := Record{Path: "/p/.byn", SHA256: "abc"}
	v1.SetMACs(fpKey, vkKey)
	if v1.IsV2() {
		t.Fatal("SetMACs: record without v2 fields must remain v1")
	}
	if !v1.VerifyFPMAC(fpKey) {
		t.Fatal("v1 SetMACs/VerifyFPMAC symmetry broken: fp MAC did not verify")
	}
	if !v1.VerifyVKMAC(vkKey) {
		t.Fatal("v1 SetMACs/VerifyVKMAC symmetry broken: vk MAC did not verify")
	}

	// v2 record: SetMACs stamps v2-domain MACs; VerifyFPMAC/VerifyVKMAC must
	// check v2-domain (not v1).
	v2 := Record{Path: "/p/.byn", SHA256: "abc", MTimeUnixNano: 1234, Snapshot: "s"}
	v2.SetMACs(fpKey, vkKey)
	if !v2.IsV2() {
		t.Fatal("SetMACs: record with v2 fields must be v2")
	}
	if !v2.VerifyFPMAC(fpKey) {
		t.Fatal("v2 SetMACs/VerifyFPMAC symmetry broken: fp MAC did not verify")
	}
	if !v2.VerifyVKMAC(vkKey) {
		t.Fatal("v2 SetMACs/VerifyVKMAC symmetry broken: vk MAC did not verify")
	}

	// Cross-version: a v1 MAC must NOT pass v2 verification and vice versa.
	// Manually set v2 fields on the previously-v1 record after minting v1 MACs
	// to simulate a record that IsV2() but has v1-domain MACs.
	hybrid := v1 // copy with v1-domain MACs
	hybrid.MTimeUnixNano = 9999
	hybrid.Snapshot = "injected"
	if !hybrid.IsV2() {
		t.Fatal("hybrid should be v2 now")
	}
	// VerifyFPMAC should FAIL because the stored MAC was built with v1 domain
	// but the record is now v2 (VerifyFPMAC will try v2 preimage).
	if hybrid.VerifyFPMAC(fpKey) {
		t.Fatal("v1 MAC accepted by v2 VerifyFPMAC — symmetry trap triggered")
	}
}

// ---- JSON round-trip of new fields ------------------------------------------

// TestV2_JSONRoundTrip verifies that all v2 fields survive a JSON encode/decode
// cycle intact.
func TestV2_JSONRoundTrip(t *testing.T) {
	fpKey, vkKey := key(0x01), key(0x02)
	original := makeV2Rec("/p/.byn", "deadbeef", fpKey, vkKey)

	body, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded Record
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(original, decoded) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", decoded, original)
	}
	if !decoded.VerifyFPMAC(fpKey) || !decoded.VerifyVKMAC(vkKey) {
		t.Fatal("MACs must survive JSON round-trip")
	}
	// Spot-check each v2 field.
	if decoded.MTimeUnixNano != original.MTimeUnixNano {
		t.Errorf("MTimeUnixNano mismatch")
	}
	if decoded.Snapshot != original.Snapshot {
		t.Errorf("Snapshot mismatch")
	}
	if !reflect.DeepEqual(decoded.Actions, original.Actions) {
		t.Errorf("Actions mismatch: %v vs %v", decoded.Actions, original.Actions)
	}
	if !reflect.DeepEqual(decoded.Auth, original.Auth) {
		t.Errorf("Auth mismatch: %v vs %v", decoded.Auth, original.Auth)
	}
	if !reflect.DeepEqual(decoded.Aliases, original.Aliases) {
		t.Errorf("Aliases mismatch: %v vs %v", decoded.Aliases, original.Aliases)
	}
	if decoded.ScopeVault != original.ScopeVault {
		t.Errorf("ScopeVault mismatch")
	}
	if decoded.ScopeProject != original.ScopeProject {
		t.Errorf("ScopeProject mismatch")
	}
	if decoded.ScopeEnv != original.ScopeEnv {
		t.Errorf("ScopeEnv mismatch")
	}
}

// TestV2_JSONRoundTrip_OmitEmpty verifies that zero-value v2 fields do not
// appear in the JSON output (omitempty), keeping the on-disk format lean.
func TestV2_JSONRoundTrip_OmitEmpty(t *testing.T) {
	r := Record{Path: "/p/.byn", SHA256: "abc"}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"mtime_unix_nano", "snapshot", "actions", "auth",
		"aliases", "scope_vault", "scope_project", "scope_env"} {
		if _, ok := m[field]; ok {
			t.Errorf("field %q should be omitted when zero/empty", field)
		}
	}
}

// ---- IsV2 classification ----------------------------------------------------

func TestIsV2(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
		want bool
	}{
		{"zero record", Record{}, false},
		{"path+sha only", Record{Path: "/p", SHA256: "a"}, false},
		{"mtime set", Record{MTimeUnixNano: 1}, true},
		{"snapshot set", Record{Snapshot: "x"}, true},
		{"mtime+snapshot", Record{MTimeUnixNano: 1, Snapshot: "x"}, true},
		// Actions/Auth/Scope alone do NOT set v2 — only mtime or snapshot does.
		{"actions only", Record{Actions: []string{"a"}}, false},
		{"auth only", Record{Auth: map[string]string{"k": "v"}}, false},
		{"scope only", Record{ScopeVault: "v"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rec.IsV2(); got != c.want {
				t.Fatalf("IsV2 = %v, want %v", got, c.want)
			}
		})
	}
}

// ---- auth sort stability (preimage determinism) ----------------------------

// TestV2_AuthMapOrdering verifies that two records with the same auth entries
// in different insertion orders produce the same preimage (sorted keys).
func TestV2_AuthMapOrdering(t *testing.T) {
	const domain = "byn:trust-fp-mac:v2"
	const path, sha = "/p/.byn", "abc"

	r1 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: 1,
		Auth:          map[string]string{"get": "password", "exec": "password", "put": "password"},
	}
	// r2 is identical in value — map iteration in Go is random so this tests
	// that the sort makes the preimage deterministic regardless of order.
	r2 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: 1,
		Auth:          map[string]string{"exec": "password", "put": "password", "get": "password"},
	}
	p1 := macPreimageV2(domain, path, sha, &r1)
	p2 := macPreimageV2(domain, path, sha, &r2)
	if string(p1) != string(p2) {
		t.Fatal("preimage differs for maps with same entries — sort is not deterministic")
	}

	// A record with a different auth value must produce a different preimage.
	r3 := r1
	r3.Auth = map[string]string{"get": "none", "exec": "password", "put": "password"}
	p3 := macPreimageV2(domain, path, sha, &r3)
	if string(p1) == string(p3) {
		t.Fatal("identical preimage for different auth values — encoding is lossy")
	}
}

// TestV2_ActionsOrdering verifies that action ORDER is committed to
// (list semantics: ["a","b"] ≠ ["b","a"]).
func TestV2_ActionsOrdering(t *testing.T) {
	const domain = "byn:trust-fp-mac:v2"
	const path, sha = "/p/.byn", "abc"

	r1 := Record{Path: path, SHA256: sha, MTimeUnixNano: 1, Actions: []string{"a", "b"}}
	r2 := Record{Path: path, SHA256: sha, MTimeUnixNano: 1, Actions: []string{"b", "a"}}
	p1 := macPreimageV2(domain, path, sha, &r1)
	p2 := macPreimageV2(domain, path, sha, &r2)
	if string(p1) == string(p2) {
		t.Fatal("action order not committed to — list ordering is lost")
	}
}

// ---- per-alias post-MAC-edit → tampered -------------------------------------

// TestV2_PostMACEdit_Alias_Tampered verifies that editing an alias after MACs
// are stamped results in VerifyTampered — aliases are MAC-bound at grant time.
func TestV2_PostMACEdit_Alias_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		// Add a new alias after minting — the v2 preimage binds the aliases map.
		if r.Aliases == nil {
			r.Aliases = map[string]string{}
		}
		r.Aliases["evil"] = "rm -rf /"
	})
}

// TestV2_PostMACEdit_AliasValue_Tampered verifies that changing an existing
// alias value after MACs are stamped yields VerifyTampered.
func TestV2_PostMACEdit_AliasValue_Tampered(t *testing.T) {
	editAndVerify(t, func(r *Record) {
		// Change an existing alias value — both key and value are bound.
		for k := range r.Aliases {
			r.Aliases[k] = "evil-cmd --inject"
			break
		}
	})
}

// ---- alias pair encoding collision regression --------------------------------

// TestV2_AliasPairEncoding_NoCollision is a regression test for the alias
// encoding: {"a":"b=c"} and {"a=b":"c"} must produce different preimages.
// The fix writes key and value as two separate length-prefixed fields.
func TestV2_AliasPairEncoding_NoCollision(t *testing.T) {
	const domain = "byn:trust-fp-mac:v2"
	const path, sha = "/proj/.byn", "abc123"
	const mtime int64 = 1_700_000_000_000_000_000

	r1 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: mtime,
		Aliases:       map[string]string{"a": "b=c"},
	}
	r2 := Record{
		Path:          path,
		SHA256:        sha,
		MTimeUnixNano: mtime,
		Aliases:       map[string]string{"a=b": "c"},
	}

	p1 := macPreimageV2(domain, path, sha, &r1)
	p2 := macPreimageV2(domain, path, sha, &r2)
	if string(p1) == string(p2) {
		t.Fatal(`alias encoding collision: {"a":"b=c"} and {"a=b":"c"} produced the same preimage`)
	}

	// Also verify the MACs differ.
	fpKey := key(0x42)
	r1.SetMACs(fpKey, nil)
	r2.SetMACs(fpKey, nil)
	if r1.FPMAC == r2.FPMAC {
		t.Fatal(`MAC collision: {"a":"b=c"} and {"a=b":"c"} produced identical FPMACs`)
	}
}
