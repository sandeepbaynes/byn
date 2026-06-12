//go:build byntest

package paths

import "os"

// Under the byntest tag ONLY, honor BYN_TEST_DIR so integration tests that exec
// the real binary can isolate a tempdir. This file is NEVER in a production
// build (the production paths_*.go are gated on !byntest), so it is not a
// runtime attack surface (spec §6.5 decision).
func dataDir() string {
	if d := os.Getenv("BYN_TEST_DIR"); d != "" {
		return d
	}
	return "/tmp/byn-test"
}

func socketPath() string { return dataDir() + "/daemon.sock" }
