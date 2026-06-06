// Layout: tier + per-pane rectangles, computed from (width, height).
//
// Single source of truth for responsive behavior. Everywhere else in
// the TUI reads from `Layout` rather than re-checking width.
//
// See docs/tui-design.md "Layout tiers" for the breakpoint table.
package tui

// Tier is the layout breakpoint.
type Tier int

// Tier breakpoints; see docs/tui-design.md.
const (
	TierBelowMin Tier = iota
	TierTiny
	TierMedium
	TierStandard
	TierLarge
)

func (t Tier) String() string {
	switch t {
	case TierBelowMin:
		return "below-min"
	case TierTiny:
		return "tiny"
	case TierMedium:
		return "medium"
	case TierStandard:
		return "standard"
	case TierLarge:
		return "large"
	}
	return "unknown"
}

// Rect is a screen region. Zero Rect (any dimension 0) means "hidden".
type Rect struct {
	X, Y, W, H int
}

// Visible reports whether this Rect has nonzero area (i.e. should be rendered).
func (r Rect) Visible() bool { return r.W > 0 && r.H > 0 }

// Layout fully describes how to render the current frame.
type Layout struct {
	Tier      Tier
	Width     int
	Height    int
	TopBar    Rect // top breadcrumb row inside content (1 row)
	Rail      Rect
	Content   Rect
	Detail    Rect
	Status    Rect // 1 row at the bottom, always
	DateFmt   string
	AuditRows int  // 0 = audit section hidden
	ShowFiles bool // hide when tight + 0 files
}

// Compute returns the layout for a given terminal size. Pure function;
// callers re-call on every WindowSizeMsg.
func Compute(width, height int) Layout {
	l := Layout{Width: width, Height: height}

	// Below-min: both axes must clear the floor.
	if width < 40 || height < 12 {
		l.Tier = TierBelowMin
		return l
	}

	// Status line always claims 1 row at the bottom.
	statusY := height - 1
	l.Status = Rect{X: 0, Y: statusY, W: width, H: 1}

	// Tier from width.
	switch {
	case width < 60:
		l.Tier = TierTiny
		l.DateFmt = "01-02"
	case width < 90:
		l.Tier = TierMedium
		l.DateFmt = "01-02"
	case width < 120:
		l.Tier = TierStandard
		l.DateFmt = "2006-01-02"
	default:
		l.Tier = TierLarge
		l.DateFmt = "2006-01-02"
	}

	// Vertical room above the status line.
	innerH := statusY // y from 0 to statusY-1

	// Rail width per tier (0 = hidden). Gutter columns between
	// panes are accounted for here so contentW sums correctly.
	// Widths chosen so common names (default, billing, staging,
	// myapp-prod, etc.) fit at depth 2 without ellipsis.
	railW := 0
	switch l.Tier {
	case TierMedium:
		railW = 20
	case TierStandard, TierLarge:
		railW = 26
	}

	// Detail width per tier.
	detailW := 0
	if l.Tier == TierLarge {
		detailW = 32
	}

	// Gutters: 1 col between rail/content and 1 col between
	// content/detail. Subtract from contentW so the full width
	// adds up.
	gutters := 0
	if railW > 0 {
		gutters++
	}
	if detailW > 0 {
		gutters++
	}

	// TopBar is 1 row at the top of the content (NOT the rail).
	// Tiny tier: TopBar becomes the *only* navigation hint (no rail).
	topBarH := 1
	// Top bar starts at y=0; content starts below it.
	contentTop := topBarH

	// Rail spans the full inner height (top bar excluded — the rail
	// has its own header inside).
	if railW > 0 {
		l.Rail = Rect{X: 0, Y: 0, W: railW, H: innerH}
	}

	// Content: between rail and detail, full inner height.
	contentX := railW
	if railW > 0 {
		contentX++ // skip gutter
	}
	contentW := width - railW - detailW - gutters
	if contentW < 20 {
		// Pathological — collapse detail first.
		contentW = width - railW
		if railW > 0 {
			contentW--
		}
		detailW = 0
	}

	l.TopBar = Rect{X: contentX, Y: 0, W: contentW, H: topBarH}
	l.Content = Rect{X: contentX, Y: contentTop, W: contentW, H: innerH - contentTop}

	if detailW > 0 {
		l.Detail = Rect{X: contentX + contentW, Y: 0, W: detailW, H: innerH}
	}

	// Audit row count + section visibility from vertical room.
	l.AuditRows = auditRowsFor(l.Tier, innerH)
	l.ShowFiles = innerH >= 20

	return l
}

func auditRowsFor(tier Tier, innerH int) int {
	if tier == TierTiny {
		return 0
	}
	switch {
	case innerH < 14:
		return 0
	case innerH < 22:
		return 2
	case innerH < 30:
		return 3
	default:
		return 5
	}
}
