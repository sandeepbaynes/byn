package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// legacyDirName is the per-user legacy data dir basename (~/.byn) that predates
// the system data root. `byn setup` relocates it into the system path when the
// invoking human has one.
const legacyDirName = ".byn"

// resolveSudoUID returns the INVOKING HUMAN's UID — the owner to allowlist on
// the peercred-gated socket — by reading the SUDO_UID env var sudo sets. It
// returns (uid, true) only for a real, positive UID. (0, false) means either
// SUDO_UID is unset (byn was run as real root, not via sudo) or it is 0/garbage;
// the caller turns that into a hard error rather than recording owner UID 0,
// which would allowlist root and defeat privsep. getenv is injected so the
// resolution is unit-testable without manipulating the process environment.
func resolveSudoUID(getenv func(string) string) (int, bool) {
	raw := getenv("SUDO_UID")
	if raw == "" {
		return 0, false
	}
	uid, err := strconv.Atoi(raw)
	if err != nil || uid <= 0 {
		return 0, false
	}
	return uid, true
}

// resolveLegacyDir resolves the invoking human's legacy ~/.byn and whether it
// exists, so `byn setup` relocates the right person's vault — NOT root's home.
// Under sudo the process home is root's; the human is SUDO_USER, so we look up
// that account's home dir. getenv + lookup + stat are injected for testability.
//
//   - No SUDO_USER (run as real root, not via sudo): there is no human home to
//     migrate from, so report (no dir, exists=false, nil) — a fresh-install skip.
//     (The owner-UID resolution already hard-errors on the no-sudo case; legacy
//     migration simply has nothing to do.)
//   - SUDO_USER set but unknown to the user db: a hard error (the caller asked us
//     to migrate but we cannot find them).
//   - Home found: dir = <home>/.byn; exists reflects a stat of that path.
func resolveLegacyDir(
	getenv func(string) string,
	lookup func(string) (*user.User, error),
	stat func(string) (os.FileInfo, error),
) (dir string, exists bool, err error) {
	sudoUser := getenv("SUDO_USER")
	if sudoUser == "" {
		return "", false, nil
	}
	u, lerr := lookup(sudoUser)
	if lerr != nil {
		return "", false, fmt.Errorf("look up invoking user %q: %w", sudoUser, lerr)
	}
	if u.HomeDir == "" {
		return "", false, fmt.Errorf("invoking user %q has no home directory", sudoUser)
	}
	dir = filepath.Join(u.HomeDir, legacyDirName)
	if _, serr := stat(dir); serr != nil {
		if os.IsNotExist(serr) {
			return dir, false, nil
		}
		return "", false, fmt.Errorf("stat legacy data dir %s: %w", dir, serr)
	}
	return dir, true, nil
}
