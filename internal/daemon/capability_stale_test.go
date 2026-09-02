package daemon

import (
	"strings"
	"testing"
)

// TestStaleCapabilityMessage_DoesNotCryCorruption guards the wording, because
// the wording is the bug that was reported.
//
// A field report spent real time diagnosing data corruption after seeing:
//
//	decrypt "INTEGRATION_CONFIG_ENCRYPTION_KEY" via capability:
//	vault/crypto: wrapped key tampered or corrupted
//
// Nothing was corrupted. A capability holds the key that opened a row at grant
// time, and an inherited value that is later overridden in this env moves to a
// different row under a different key — so the captured key stops working and
// the AEAD failure is reported as tampering. `byn trust` fixes it in a second.
//
// Two conditions, one message, and the recoverable one was wearing the
// unrecoverable one's wording. On a vault holding the only copy of an
// encryption key, "tampered or corrupted" means "your secret is gone", and
// that is not a thing to say when it is not true.
func TestStaleCapabilityMessage_DoesNotCryCorruption(t *testing.T) {
	msg, hint := staleCapabilityText("INTEGRATION_CONFIG_ENCRYPTION_KEY", "/p/services/api/.byn")

	for _, alarming := range []string{"tampered", "corrupt"} {
		if strings.Contains(strings.ToLower(msg+hint), alarming) {
			t.Errorf("a recoverable stale grant must not use the word %q: %q / %q",
				alarming, msg, hint)
		}
	}
	if !strings.Contains(msg, "INTEGRATION_CONFIG_ENCRYPTION_KEY") {
		t.Errorf("the message must name the variable that failed: %q", msg)
	}
	// The remedy has to be in the text. The reporter found it by guessing.
	if !strings.Contains(hint, "byn trust") {
		t.Errorf("the recovery hint must name the fix: %q", hint)
	}
	if !strings.Contains(hint, "/p/services/api/.byn") {
		t.Errorf("the hint must name WHICH .byn to re-trust: %q", hint)
	}
	// And it must say the data is fine, since the previous wording said the
	// opposite and that is what caused the detour.
	if !strings.Contains(hint, "intact") {
		t.Errorf("the hint must say the value is not damaged: %q", hint)
	}
}
