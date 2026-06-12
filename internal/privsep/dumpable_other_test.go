//go:build !linux

package privsep

import "testing"

// Off Linux, SetUndumpable is a no-op that MUST return nil — the daemon and the
// exec child call it unconditionally, so it has to be safe to call on every
// platform. (macOS memory hardening is a build/sign-time concern; see
// .goreleaser.yaml + docs/security.md.)
func TestSetUndumpable_NoOpOffLinux(t *testing.T) {
	if err := SetUndumpable(); err != nil {
		t.Fatalf("SetUndumpable() = %v, want nil (no-op off Linux)", err)
	}
}
