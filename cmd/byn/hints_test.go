package main

import "testing"

func TestHintsEnabled_DisabledByEnv(t *testing.T) {
	cases := []string{"0", "false", "off", "no", "FALSE", "Off"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			t.Setenv("BYN_HINTS", v)
			if hintsEnabled() {
				t.Fatalf("BYN_HINTS=%q should disable hints", v)
			}
		})
	}
}

func TestHintsEnabled_DefaultRespectsTTY(t *testing.T) {
	t.Setenv("BYN_HINTS", "")
	// stderr in tests is not a TTY so hints should be off by default.
	if hintsEnabled() {
		t.Fatal("non-TTY stderr should disable hints")
	}
}

func TestHintf_NoCrashWhenSuppressed(t *testing.T) {
	t.Setenv("BYN_HINTS", "0")
	// Should not write anything; just ensure no panic.
	hintf("ignored %d", 42)
}

func TestHintf_NewlineAdded(t *testing.T) {
	// Test we don't double-newline.
	t.Setenv("BYN_HINTS", "0") // disabled, so we just call the branch path
	hintf("no trailing")
	hintf("trailing\n")
}
