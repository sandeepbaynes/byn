package tui

import "testing"

func TestCompute_BelowMin(t *testing.T) {
	tests := []struct {
		w, h int
		want Tier
	}{
		{39, 24, TierBelowMin},
		{100, 11, TierBelowMin},
		{30, 10, TierBelowMin},
	}
	for _, tt := range tests {
		got := Compute(tt.w, tt.h).Tier
		if got != tt.want {
			t.Errorf("Compute(%d,%d) tier = %v, want %v", tt.w, tt.h, got, tt.want)
		}
	}
}

func TestCompute_TierBoundaries(t *testing.T) {
	tests := []struct {
		w, h int
		want Tier
	}{
		{40, 12, TierTiny},
		{59, 24, TierTiny},
		{60, 24, TierMedium},
		{89, 24, TierMedium},
		{90, 30, TierStandard},
		{119, 30, TierStandard},
		{120, 40, TierLarge},
		{200, 40, TierLarge},
	}
	for _, tt := range tests {
		got := Compute(tt.w, tt.h).Tier
		if got != tt.want {
			t.Errorf("Compute(%d,%d) tier = %v, want %v", tt.w, tt.h, got, tt.want)
		}
	}
}

func TestCompute_RailHiddenOnTiny(t *testing.T) {
	l := Compute(50, 24)
	if l.Rail.Visible() {
		t.Errorf("Tiny tier should hide rail; got %+v", l.Rail)
	}
}

func TestCompute_DetailOnlyOnLarge(t *testing.T) {
	if l := Compute(100, 30); l.Detail.Visible() {
		t.Errorf("Standard tier should not show detail; got %+v", l.Detail)
	}
	if l := Compute(140, 30); !l.Detail.Visible() {
		t.Errorf("Large tier should show detail; got %+v", l.Detail)
	}
}

func TestCompute_StatusAlwaysOneRow(t *testing.T) {
	for _, sz := range []struct{ w, h int }{
		{50, 20}, {80, 24}, {120, 40},
	} {
		l := Compute(sz.w, sz.h)
		if l.Status.H != 1 || l.Status.W != sz.w {
			t.Errorf("Compute(%d,%d) status = %+v, want full-width 1-row", sz.w, sz.h, l.Status)
		}
	}
}

func TestCompute_AuditRowsScale(t *testing.T) {
	if Compute(100, 13).AuditRows != 0 {
		t.Errorf("Very-short terminal should hide audit; got non-zero rows")
	}
	if Compute(100, 22).AuditRows == 0 {
		t.Errorf("Medium-height terminal should show audit")
	}
	if Compute(100, 50).AuditRows < 3 {
		t.Errorf("Tall terminal should show more audit rows")
	}
}
