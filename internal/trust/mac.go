package trust

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
)

// Trust-store tamper-evidence. Each Record carries two HMAC-SHA-256 tags over a
// domain-separated, length-delimited preimage of (path, content-hash, and for v2
// all policy/scope fields):
//
//   - FPMAC, keyed by a machine-fingerprint-derived key — verifiable while the
//     vault is LOCKED, so it gates discovery and rejects a record minted on a
//     different machine (or hand-crafted offline and copied in).
//   - VKMAC, keyed by a vault-key-derived key — verified at USE-TIME (when a
//     value would actually flow, vault unlocked), so it rejects a same-UID
//     forge: minting it requires the vault key, which requires the password.
//
// The keys are derived and held by the daemon (mac.go is key-agnostic: callers
// pass the already-derived 32-byte keys). The domains differ so an FPMAC can
// never be replayed as a VKMAC or vice versa.
//
// v1 domains cover (domain, path, sha256).
// v2 domains cover all of the above plus mtime, snapshot-hash, actions, auth,
// and scope fields — binding the full policy at grant time.
const (
	fpMACDomainV1 = "byn:trust-fp-mac:v1" // machine-fingerprint layer (v1)
	vkMACDomainV1 = "byn:trust-vk-mac:v1" // vault-key layer (v1)
	fpMACDomainV2 = "byn:trust-fp-mac:v2" // machine-fingerprint layer (v2)
	vkMACDomainV2 = "byn:trust-vk-mac:v2" // vault-key layer (v2)

	// Keep the old names as aliases used in existing tests and internal code.
	fpMACDomain = fpMACDomainV1
	vkMACDomain = vkMACDomainV1
)

// VKMACKeyInfo is the HKDF info label the daemon passes to
// vault.Store.DeriveSubkey to derive the vault-key MAC key. Exported because
// that derivation lives in the vault layer while the MAC itself lives here.
const VKMACKeyInfo = "byn:trust-store-mac:v1"

// writeField appends a 4-byte big-endian length prefix followed by the field
// bytes to b. This encoding is shared by v1 and v2 preimage builders so field
// boundaries are always unambiguous.
func writeField(b []byte, f string) []byte {
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(f))) // #nosec G115 -- field lengths are tiny, never near 2^32
	b = append(b, lenbuf[:]...)
	b = append(b, f...)
	return b
}

// macPreimage builds the v1 message a record's MAC commits to: each field is
// length-prefixed (4-byte big-endian) so field boundaries are unambiguous —
// (path="a", sha="bc") and (path="ab", sha="c") produce different preimages.
// The domain is included so the two MAC layers can never collide.
func macPreimage(domain, path, sha256hex string) []byte {
	fields := [...]string{domain, path, sha256hex}
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	b := make([]byte, 0, n)
	for _, f := range fields {
		b = writeField(b, f)
	}
	return b
}

// macPreimageV2 builds the v2 message that additionally commits to vault,
// mtime, snapshot hash, actions, auth, scope, and aliases. Every field is
// length-prefixed so boundaries remain unambiguous. The action list, auth map,
// and aliases map are encoded in a deterministic order.
//
// Field order (each length-prefixed unless noted):
//  1. domain
//  2. path
//  3. sha256hex
//  4. vault (r.Vault — binds the target vault; a Vault swap must flip the MAC)
//  5. mtime (decimal string of r.MTimeUnixNano)
//  6. snapshot hash (hex(sha256(r.Snapshot)))
//  7. actions count (4-byte BE), then each action length-prefixed
//  8. auth count (4-byte BE), then each pair as two consecutive length-prefixed
//     fields (key, value) sorted by key — encoding key and value separately
//     prevents {"a":"b=c"} and {"a=b":"c"} from colliding
//  9. scope_vault
//  10. scope_project
//  11. scope_env
//  12. aliases count (4-byte BE), then each pair as two consecutive length-prefixed
//     fields (key, value) sorted by key — same {"a":"b=c"} anti-collision
//     encoding as auth
func macPreimageV2(domain, path, sha256hex string, r *Record) []byte {
	b := make([]byte, 0, 256)

	// Core fields — same order as v1 so the first three fields match.
	b = writeField(b, domain)
	b = writeField(b, path)
	b = writeField(b, sha256hex)

	// Vault: binds the target vault so a Vault-field swap flips the MAC.
	b = writeField(b, r.Vault)

	// mtime as decimal string.
	b = writeField(b, strconv.FormatInt(r.MTimeUnixNano, 10))

	// Snapshot committed as hex(sha256(snapshot)) so the preimage doesn't
	// balloon for large files while still binding the full content.
	snapHash := sha256.Sum256([]byte(r.Snapshot))
	b = writeField(b, hex.EncodeToString(snapHash[:]))

	// Actions: count (4-byte BE) then each action length-prefixed.
	var countBuf [4]byte
	binary.BigEndian.PutUint32(countBuf[:], uint32(len(r.Actions))) // #nosec G115 -- slice lengths are tiny
	b = append(b, countBuf[:]...)
	for _, a := range r.Actions {
		b = writeField(b, a)
	}

	// Auth: count (4-byte BE) then sorted key/value pairs. Each pair is encoded
	// as two consecutive length-prefixed fields (key then value) so that
	// {"a":"b=c"} and {"a=b":"c"} never collide.
	keys := make([]string, 0, len(r.Auth))
	for k := range r.Auth {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	binary.BigEndian.PutUint32(countBuf[:], uint32(len(r.Auth))) // #nosec G115 -- map lengths are tiny
	b = append(b, countBuf[:]...)
	for _, k := range keys {
		b = writeField(b, k)
		b = writeField(b, r.Auth[k])
	}

	// Scope triple.
	b = writeField(b, r.ScopeVault)
	b = writeField(b, r.ScopeProject)
	b = writeField(b, r.ScopeEnv)

	// Aliases: count (4-byte BE) then sorted key/value pairs. Encoding is
	// identical to Auth — two consecutive length-prefixed fields per pair so
	// that {"a":"b=c"} and {"a=b":"c"} never collide.
	aliasKeys := make([]string, 0, len(r.Aliases))
	for k := range r.Aliases {
		aliasKeys = append(aliasKeys, k)
	}
	sort.Strings(aliasKeys)
	binary.BigEndian.PutUint32(countBuf[:], uint32(len(r.Aliases))) // #nosec G115 -- map lengths are tiny
	b = append(b, countBuf[:]...)
	for _, k := range aliasKeys {
		b = writeField(b, k)
		b = writeField(b, r.Aliases[k])
	}

	return b
}

// IsV2 reports whether this record carries v2 fields (mtime or snapshot set at
// grant time). A record without these is a v1 record (pre-mtime hardening) and
// uses the v1 MAC domain so it verifies as authentic but stale.
func (r *Record) IsV2() bool {
	return r.MTimeUnixNano != 0 || r.Snapshot != ""
}

// computeMAC returns hex(HMAC-SHA-256(key, preimage(domain, path, sha))).
func computeMAC(key []byte, domain, path, sha256hex string) string {
	m := hmac.New(sha256.New, key)
	m.Write(macPreimage(domain, path, sha256hex))
	return hex.EncodeToString(m.Sum(nil))
}

// computeMACv2 returns hex(HMAC-SHA-256(key, preimageV2(domain, path, sha, r))).
func computeMACv2(key []byte, domain, path, sha256hex string, r *Record) string {
	m := hmac.New(sha256.New, key)
	m.Write(macPreimageV2(domain, path, sha256hex, r))
	return hex.EncodeToString(m.Sum(nil))
}

// SetMACs stamps the record's MAC tags. A nil key skips that layer (so a caller
// that only has the machine key can still write the FPMAC); in practice the
// daemon passes both, because a grant requires the target vault unlocked.
//
// Domain choice follows IsV2(): v2 fields present → v2-domain MACs; absent →
// v1-domain MACs (preserving today's behavior for records not yet upgraded).
// This symmetry ensures VerifyFPMAC/VerifyVKMAC — which also branch on IsV2()
// — will always check the matching preimage.
func (r *Record) SetMACs(fpKey, vkKey []byte) {
	if r.IsV2() {
		if fpKey != nil {
			r.FPMAC = computeMACv2(fpKey, fpMACDomainV2, r.Path, r.SHA256, r)
		}
		if vkKey != nil {
			r.VKMAC = computeMACv2(vkKey, vkMACDomainV2, r.Path, r.SHA256, r)
		}
	} else {
		if fpKey != nil {
			r.FPMAC = computeMAC(fpKey, fpMACDomainV1, r.Path, r.SHA256)
		}
		if vkKey != nil {
			r.VKMAC = computeMAC(vkKey, vkMACDomainV1, r.Path, r.SHA256)
		}
	}
}

// VerifyFPMAC reports whether the machine-fingerprint MAC is present and valid
// under fpKey, compared in constant time. A missing tag is invalid by design —
// pre-hardening records have no FPMAC and must be re-trusted.
//
// Domain choice mirrors SetMACs: v2 records verify against the v2 preimage,
// v1 records against the v1 preimage.
func (r Record) VerifyFPMAC(fpKey []byte) bool {
	if r.IsV2() {
		return verifyMACv2(r.FPMAC, fpKey, fpMACDomainV2, r.Path, r.SHA256, &r)
	}
	return verifyMAC(r.FPMAC, fpKey, fpMACDomain, r.Path, r.SHA256)
}

// VerifyVKMAC reports whether the vault-key MAC is present and valid under
// vkKey (the HKDF-derived key for r's target vault), compared in constant time.
//
// Domain choice mirrors SetMACs: v2 records verify against the v2 preimage,
// v1 records against the v1 preimage.
func (r Record) VerifyVKMAC(vkKey []byte) bool {
	if r.IsV2() {
		return verifyMACv2(r.VKMAC, vkKey, vkMACDomainV2, r.Path, r.SHA256, &r)
	}
	return verifyMAC(r.VKMAC, vkKey, vkMACDomain, r.Path, r.SHA256)
}

func verifyMAC(tag string, key []byte, domain, path, sha256hex string) bool {
	if tag == "" || len(key) == 0 {
		return false
	}
	want := computeMAC(key, domain, path, sha256hex)
	return hmac.Equal([]byte(want), []byte(tag))
}

func verifyMACv2(tag string, key []byte, domain, path, sha256hex string, r *Record) bool {
	if tag == "" || len(key) == 0 {
		return false
	}
	want := computeMACv2(key, domain, path, sha256hex, r)
	return hmac.Equal([]byte(want), []byte(tag))
}
