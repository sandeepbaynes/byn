package trust

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Trust-store tamper-evidence. Each Record carries two HMAC-SHA-256 tags over a
// domain-separated, length-delimited preimage of (path, content-hash):
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
const (
	fpMACDomain = "byn:trust-fp-mac:v1" // machine-fingerprint layer
	vkMACDomain = "byn:trust-vk-mac:v1" // vault-key layer
)

// macPreimage builds the message a record's MAC commits to: each field is
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
	var lenbuf [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(lenbuf[:], uint32(len(f))) // #nosec G115 -- field lengths (domain/path/hash) are tiny, never near 2^32
		b = append(b, lenbuf[:]...)
		b = append(b, f...)
	}
	return b
}

// computeMAC returns hex(HMAC-SHA-256(key, preimage(domain, path, sha))).
func computeMAC(key []byte, domain, path, sha256hex string) string {
	m := hmac.New(sha256.New, key)
	m.Write(macPreimage(domain, path, sha256hex))
	return hex.EncodeToString(m.Sum(nil))
}

// SetMACs stamps the record's MAC tags. A nil key skips that layer (so a caller
// that only has the machine key can still write the FPMAC); in practice the
// daemon passes both, because a grant requires the target vault unlocked.
func (r *Record) SetMACs(fpKey, vkKey []byte) {
	if fpKey != nil {
		r.FPMAC = computeMAC(fpKey, fpMACDomain, r.Path, r.SHA256)
	}
	if vkKey != nil {
		r.VKMAC = computeMAC(vkKey, vkMACDomain, r.Path, r.SHA256)
	}
}

// VerifyFPMAC reports whether the machine-fingerprint MAC is present and valid
// under fpKey, compared in constant time. A missing tag is invalid by design —
// pre-hardening records have no FPMAC and must be re-trusted.
func (r Record) VerifyFPMAC(fpKey []byte) bool {
	return verifyMAC(r.FPMAC, fpKey, fpMACDomain, r.Path, r.SHA256)
}

// VerifyVKMAC reports whether the vault-key MAC is present and valid under
// vkKey (the HKDF-derived key for r's target vault), compared in constant time.
func (r Record) VerifyVKMAC(vkKey []byte) bool {
	return verifyMAC(r.VKMAC, vkKey, vkMACDomain, r.Path, r.SHA256)
}

func verifyMAC(tag string, key []byte, domain, path, sha256hex string) bool {
	if tag == "" || len(key) == 0 {
		return false
	}
	want := computeMAC(key, domain, path, sha256hex)
	return hmac.Equal([]byte(want), []byte(tag))
}
