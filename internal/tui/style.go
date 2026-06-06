// Styles: lipgloss styles honoring NO_COLOR / FORCE_COLOR.
package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

// Styles bundles the styles used across panes. Built once at startup
// and passed by value (lipgloss styles are cheap to copy).
type Styles struct {
	// Top bar
	AppName    lipgloss.Style
	Breadcrumb lipgloss.Style
	StatusChip lipgloss.Style

	// Rail
	RailNode       lipgloss.Style
	RailNodeOpen   lipgloss.Style
	RailSelected   lipgloss.Style
	RailUnselected lipgloss.Style
	RailDim        lipgloss.Style
	RailMarker     lipgloss.Style

	// Content
	SectionHeader lipgloss.Style
	Divider       lipgloss.Style
	EntryName     lipgloss.Style
	EntryMasked   lipgloss.Style
	EntryMeta     lipgloss.Style
	EntrySelected lipgloss.Style
	Action        lipgloss.Style
	Placeholder   lipgloss.Style

	// Audit
	AuditOK     lipgloss.Style
	AuditDenied lipgloss.Style
	AuditError  lipgloss.Style

	// Inheritance badges shown on every entry row in non-default envs.
	StatusInherited  lipgloss.Style // ↓ dim cyan — value comes from default
	StatusOverridden lipgloss.Style // ⤴ yellow — also in default; this env wins
	StatusNew        lipgloss.Style // ✦ green — created in this env only

	// Detail
	DetailTitle  lipgloss.Style
	DetailLabel  lipgloss.Style
	DetailValue  lipgloss.Style
	DetailWarn   lipgloss.Style
	DetailDivide lipgloss.Style

	// Status line
	ModeNormal   lipgloss.Style
	ModeInsert   lipgloss.Style
	ModeReveal   lipgloss.Style
	ModeCommand  lipgloss.Style
	ModeSearch   lipgloss.Style
	ModeAudit    lipgloss.Style
	ModeHelp     lipgloss.Style
	ModeScope    lipgloss.Style
	ModeConfirm  lipgloss.Style
	StatusHint   lipgloss.Style
	StatusInline lipgloss.Style

	// Box around editors / modals
	EditBox  lipgloss.Style
	ErrorBox lipgloss.Style
	Modal    lipgloss.Style
	Error    lipgloss.Style
}

// NewStyles builds the global Styles bundle, honoring NO_COLOR /
// FORCE_COLOR.
func NewStyles() Styles {
	color := useColor()
	c := func(s string) lipgloss.Color {
		if !color {
			return ""
		}
		return lipgloss.Color(s)
	}

	return Styles{
		AppName:    lipgloss.NewStyle().Bold(true).Foreground(c("6")),
		Breadcrumb: lipgloss.NewStyle().Bold(true),
		StatusChip: lipgloss.NewStyle().Faint(true),

		RailNode:       lipgloss.NewStyle(),
		RailNodeOpen:   lipgloss.NewStyle().Bold(true),
		RailSelected:   lipgloss.NewStyle().Bold(true).Foreground(c("2")),
		RailUnselected: lipgloss.NewStyle().Faint(true),
		RailDim:        lipgloss.NewStyle().Faint(true),
		RailMarker:     lipgloss.NewStyle().Faint(true),

		SectionHeader: lipgloss.NewStyle().Bold(true),
		Divider:       lipgloss.NewStyle().Faint(true),
		EntryName:     lipgloss.NewStyle(),
		EntryMasked:   lipgloss.NewStyle().Faint(true),
		EntryMeta:     lipgloss.NewStyle().Faint(true),
		EntrySelected: lipgloss.NewStyle().Reverse(true),
		Action:        lipgloss.NewStyle().Faint(true).Italic(true),
		Placeholder:   lipgloss.NewStyle().Faint(true),

		AuditOK:     lipgloss.NewStyle().Foreground(c("2")),
		AuditDenied: lipgloss.NewStyle().Foreground(c("1")),
		AuditError:  lipgloss.NewStyle().Foreground(c("1")).Bold(true),

		StatusInherited:  lipgloss.NewStyle().Foreground(c("6")).Faint(true),
		StatusOverridden: lipgloss.NewStyle().Foreground(c("3")).Bold(true),
		StatusNew:        lipgloss.NewStyle().Foreground(c("2")).Bold(true),

		DetailTitle:  lipgloss.NewStyle().Bold(true),
		DetailLabel:  lipgloss.NewStyle().Faint(true),
		DetailValue:  lipgloss.NewStyle(),
		DetailWarn:   lipgloss.NewStyle().Foreground(c("3")).Bold(true),
		DetailDivide: lipgloss.NewStyle().Faint(true),

		ModeNormal:   lipgloss.NewStyle().Faint(true),
		ModeInsert:   lipgloss.NewStyle().Bold(true).Foreground(c("6")),
		ModeReveal:   lipgloss.NewStyle().Bold(true).Foreground(c("1")),
		ModeCommand:  lipgloss.NewStyle().Bold(true).Foreground(c("4")),
		ModeSearch:   lipgloss.NewStyle().Bold(true).Foreground(c("5")),
		ModeAudit:    lipgloss.NewStyle().Bold(true).Foreground(c("6")),
		ModeHelp:     lipgloss.NewStyle().Bold(true).Foreground(c("6")),
		ModeScope:    lipgloss.NewStyle().Bold(true).Foreground(c("6")),
		ModeConfirm:  lipgloss.NewStyle().Bold(true).Foreground(c("1")),
		StatusHint:   lipgloss.NewStyle().Faint(true),
		StatusInline: lipgloss.NewStyle(),

		EditBox:  lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(c("6")),
		ErrorBox: lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(c("1")).Bold(true),
		Modal:    lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 2),
		Error:    lipgloss.NewStyle().Foreground(c("1")).Bold(true),
	}
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	// bubbletea handles TTY detection; if we ever render to non-TTY
	// (tests, redirected), Go's stdout-isatty equivalent is fine here.
	// We default to enabled — lipgloss handles ANSI sequences cleanly
	// when output is captured.
	return true
}
