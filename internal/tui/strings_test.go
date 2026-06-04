package tui

import "testing"

func TestTier_String(t *testing.T) {
	cases := map[Tier]string{
		TierBelowMin: "below-min",
		TierTiny:     "tiny",
		TierMedium:   "medium",
		TierStandard: "standard",
		TierLarge:    "large",
		Tier(99):     "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d -> %q, want %q", k, got, want)
		}
	}
}

func TestMode_String(t *testing.T) {
	cases := map[Mode]string{
		ModeNormal:        "NORMAL",
		ModeInsert:        "INSERT",
		ModeAdd:           "INSERT",
		ModeReveal:        "REVEALED",
		ModeConfirmDelete: "CONFIRM",
		ModeScopePicker:   "SCOPE",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("%d -> %q, want %q", k, got, want)
		}
	}
}

func TestRect_Visible(t *testing.T) {
	if (Rect{}).Visible() {
		t.Fatal("zero Rect should not be visible")
	}
	if !(Rect{W: 1, H: 1}).Visible() {
		t.Fatal("1x1 should be visible")
	}
	if (Rect{W: 0, H: 5}).Visible() {
		t.Fatal("W=0 not visible")
	}
}
