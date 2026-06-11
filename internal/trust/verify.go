package trust

// Hardened-store operations: writing full records (with MACs) and deciding the
// trust status of a `.byn` against the store, checking whichever MAC layers are
// available. The MAC keys are derived and supplied by the daemon (see mac.go);
// this file is pure given (record, keys, current hash), so it is unit-testable
// without a daemon.

// VerifyStatus is the outcome of checking a `.byn` against the hardened store.
type VerifyStatus string

const (
	// VerifyTrusted means the record is present, the content matches, and every
	// checkable MAC verified.
	VerifyTrusted VerifyStatus = "trusted"
	// VerifyChanged means a record exists but the `.byn` content hash differs,
	// OR (for v2 records) the mtime differs from when trust was granted.
	VerifyChanged VerifyStatus = "changed"
	// VerifyUntrusted means no record exists for this path (first use).
	VerifyUntrusted VerifyStatus = "untrusted"
	// VerifyStale means the record matches but either predates MAC hardening (no
	// MACs) or is a v1 record (pre-mtime hardening) — it must be re-trusted to
	// gain full tamper protection.
	VerifyStale VerifyStatus = "stale"
	// VerifyTampered means the record matches but a checked MAC is invalid — the
	// record was forged or copied from another machine.
	VerifyTampered VerifyStatus = "tampered"
)

// Put inserts or updates the full record for rec.Path (MACs included). Reports
// changed=true when a record already existed with a different content hash. The
// daemon is the only writer (it holds the MAC keys).
func Put(dir string, rec Record) (changed bool, err error) {
	s, err := Load(dir)
	if err != nil {
		return false, err
	}
	for i, r := range s.Records {
		if r.Path == rec.Path {
			changed = r.SHA256 != rec.SHA256
			s.Records[i] = rec
			return changed, Save(dir, s)
		}
	}
	s.Records = append(s.Records, rec)
	return false, Save(dir, s)
}

// Lookup returns the record for a canonical path, if present.
func Lookup(dir, path string) (Record, bool, error) {
	s, err := Load(dir)
	if err != nil {
		return Record{}, false, err
	}
	for _, r := range s.Records {
		if r.Path == path {
			return r, true, nil
		}
	}
	return Record{}, false, nil
}

// Verify decides the trust status of (path, currentHash, currentMTime) against
// the store.
//
// fpKey is the machine-fingerprint MAC key (verifiable while locked); pass nil
// only if the machine id is unavailable. vkKey is the vault-key MAC key, or nil
// when the target vault is locked (then the vk-MAC is skipped and the fp-MAC
// alone gates discovery). vkChecked reports whether the vk-MAC was verified.
//
// currentMTime is the file's modification time in nanoseconds (from os.Stat).
// For v2 records an mtime mismatch (same content, touched file) yields
// VerifyChanged — a change-then-revert still forces re-trust.
//
// v1 records (no mtime in the record) that have valid v1 MACs are classified
// VerifyStale (not VerifyTampered) — they are authentic but pre-upgrade; ONE
// guided re-trust upgrades them to v2. A v1 record with INVALID v1 MACs is
// VerifyTampered.
func Verify(dir, path, currentHash string, currentMTime int64, fpKey, vkKey []byte) (status VerifyStatus, vkChecked bool, err error) {
	rec, ok, err := Lookup(dir, path)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return VerifyUntrusted, false, nil
	}
	// Content-hash check — applies to all record versions.
	if rec.SHA256 != currentHash {
		return VerifyChanged, false, nil
	}
	// v2 mtime check: same content but file was touched → VerifyChanged.
	if rec.IsV2() && rec.MTimeUnixNano != currentMTime {
		return VerifyChanged, false, nil
	}
	// Records with no MACs at all predate MAC hardening entirely.
	if rec.FPMAC == "" && rec.VKMAC == "" {
		return VerifyStale, false, nil // pre-hardening record
	}
	// v1 record (has MACs but predates v2/mtime hardening): verify its v1 MACs
	// first. A v1 record with valid v1 MACs is stale (authentic but needs
	// upgrade). A v1 record with INVALID v1 MACs is tampered.
	if !rec.IsV2() {
		if fpKey != nil && !rec.VerifyFPMAC(fpKey) {
			return VerifyTampered, false, nil
		}
		if vkKey != nil && !rec.VerifyVKMAC(vkKey) {
			return VerifyTampered, true, nil
		}
		return VerifyStale, vkKey != nil, nil
	}
	// v2 record: full MAC check.
	// Machine layer — checked whenever we have the key (i.e. always, in
	// practice). A record minted on another machine fails here.
	if fpKey != nil && !rec.VerifyFPMAC(fpKey) {
		return VerifyTampered, false, nil
	}
	// Vault-key layer — only when the vault is unlocked. Defeats a same-UID
	// local forge (minting it requires the password).
	if vkKey != nil {
		if !rec.VerifyVKMAC(vkKey) {
			return VerifyTampered, true, nil
		}
		vkChecked = true
	}
	return VerifyTrusted, vkChecked, nil
}
