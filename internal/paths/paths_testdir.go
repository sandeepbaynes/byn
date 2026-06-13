//go:build byntest

package paths

import "os"

// Under the byntest tag ONLY, honor BYN_TEST_DIR so integration tests that exec
// the real binary can isolate a tempdir. This file is NEVER in a production
// build (the production paths_*.go are gated on !byntest), so it is not a
// runtime attack surface (spec §6.5 decision). The system/legacy resolution of
// a production build is bypassed entirely here — tests get one explicit root.
func dataDir() (string, error) {
	if d := os.Getenv("BYN_TEST_DIR"); d != "" {
		return d, nil
	}
	return "/tmp/byn-test", nil
}

func socketPath() string {
	d, _ := dataDir()
	return d + "/daemon.sock"
}

// systemDataDir / legacyDataDir under the byntest seam collapse to the single
// test data root. They exist only so SystemDataDir()/LegacyDataDir() compile
// under -tags byntest; tests that exercise migrate routing inject explicit dirs
// rather than relying on these (a byntest relocate from legacy==system is a
// no-op same-dir case the command guards against).
func systemDataDir() string { return testDataRoot() }

func legacyDataDir() (string, error) {
	d, err := dataDir()
	if err != nil {
		return "", err
	}
	return d + "-legacy", nil
}

// testDataRoot is the byntest data root (BYN_TEST_DIR or the fixed fallback),
// shared by dataDir and systemDataDir so they agree.
func testDataRoot() string {
	d, _ := dataDir()
	return d
}
