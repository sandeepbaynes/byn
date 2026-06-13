package privsep

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ownerRecordMode is the permission bits of the owner-UID record. It is
// world-readable (0444) on purpose: the daemon runs as _byn (≠ the human
// owner) and must be able to read which UID to allowlist, but the file records
// only a non-secret integer (the owner's UID), so there is nothing to hide. It
// is read-only so neither the _byn daemon nor a stray process can rewrite the
// allowlisted UID without going through `byn setup` (which runs privileged and
// owns the parent dir).
const ownerRecordMode = 0o444

// WriteOwnerRecord records the allowlisted owner UID at path as decimal text,
// 0444, written atomically (temp file in the same dir + rename) so a concurrent
// ReadOwnerRecord never observes a partial write. It is called by `byn setup`
// while still privileged; the parent directory must already exist (created by
// setup while it owns it — Task 10). uid must be a real owner UID (> 0): a
// recorded owner UID of 0 would allowlist root, defeating the privsep model, so
// it is refused here as well as on read.
func WriteOwnerRecord(path string, uid int) error {
	if uid <= 0 {
		return fmt.Errorf("privsep: refusing to record owner uid %d (must be > 0)", uid)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".owner.tmp") // #nosec G304 -- setup-owned dir
	if err != nil {
		return fmt.Errorf("privsep: write owner record (tmp create): %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if any step before the rename fails.
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := fmt.Fprintf(tmp, "%d\n", uid); err != nil {
		cleanup()
		return fmt.Errorf("privsep: write owner record (write): %w", err)
	}
	// Set the final mode on the temp file before the rename so the record is
	// never momentarily group/other-writable at its destination path.
	if err := tmp.Chmod(ownerRecordMode); err != nil {
		cleanup()
		return fmt.Errorf("privsep: write owner record (chmod): %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("privsep: write owner record (close): %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("privsep: write owner record (rename): %w", err)
	}
	return nil
}

// ReadOwnerRecord returns the allowlisted owner UID recorded at path. It
// returns a clear error when the record is missing, empty, or not a positive
// integer; the daemon turns a missing record into "not provisioned — run
// `byn setup`". Validating uid > 0 rejects both a corrupt/garbage record and a
// record of 0 (which would allowlist root).
func ReadOwnerRecord(path string) (int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- daemon-owned dir
	if err != nil {
		return 0, fmt.Errorf("privsep: read owner record: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, fmt.Errorf("privsep: owner record %s is empty", path)
	}
	// Parse with an explicit 32-bit bound so the value is provably within the
	// kernel UID range (uint32) before any downstream uint32 conversion — Atoi
	// would admit an out-of-range int that silently wraps when narrowed.
	uid64, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("privsep: owner record %s has bad content %q: %w", path, s, err)
	}
	uid := int(uid64) // bounded to [0, math.MaxUint32] by ParseUint bitSize=32
	if uid <= 0 {
		return 0, fmt.Errorf("privsep: owner record %s has invalid uid %d (must be > 0)", path, uid)
	}
	return uid, nil
}
