//go:build byntest

package main

import "os"

// testUnprovisionedEnv makes byn behave as if privsep were not provisioned.
//
// End-to-end tests drive their own daemon inside a temp data dir. On a machine
// where byn is actually installed with privsep, they could not: `byn start`
// correctly refuses to spawn a daemon as the owner and points at
// `sudo byn restart`, so every one of them failed on the maintainer's own
// machine while passing in CI, where byn is not provisioned. That left the
// integration suite runnable only by CI — and an interface change that broke it
// was found after the push instead of before.
//
// Honoured only under the byntest build tag, so the shipping binary has no such
// switch. The privsep suite deliberately does NOT set it: those tests provision
// real service accounts and need the real detection.
const testUnprovisionedEnv = "BYN_TEST_UNPROVISIONED"

func forcedUnprovisioned() bool { return os.Getenv(testUnprovisionedEnv) == "1" }
