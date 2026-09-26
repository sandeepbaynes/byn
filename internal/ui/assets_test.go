package ui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// TestAssets_HiddenAttributeWins guards the bug where author `display`
// rules on .unlock/.app/.modal override the `hidden` attribute, leaving
// the modal (and app) rendered on top of the login screen. The CSS must
// force [hidden] { display: none }.
func TestAssets_HiddenAttributeWins(t *testing.T) {
	css, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	s := string(css)
	if !regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`).MatchString(s) {
		t.Error("style.css must contain `[hidden] { display: none !important; }` — " +
			"without it the unlock/app/modal overlays all render at once")
	}
}

// TestAssets_IndexWiring checks the SPA shell references the routed assets
// and the views the script toggles.
func TestAssets_IndexWiring(t *testing.T) {
	html, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		`id="app"`, `id="content-body"`, `id="dialog"`, `id="new-vault-btn"`,
		"/static/app.js", "/static/style.css",
		`id="passkey-btn"`, "/static/passkey.js",
		`id="settings-btn"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
	// The app + dialog must ship hidden so the script controls first paint.
	for _, frag := range []string{`id="app" class="app" hidden`, `id="dialog" class="dialog" hidden`} {
		if !strings.Contains(s, frag) {
			t.Errorf("index.html: expected element to start hidden: %q", frag)
		}
	}
}

// TestAssets_RevertPersistWired guards the non-default-env override actions:
// override rows get a revert + persist icon, new rows get a persist icon, and
// the undo-toast + hover styles exist. app.js has no JS test harness, so this
// presence check is the regression guard that the wiring is not silently lost.
func TestAssets_RevertPersistWired(t *testing.T) {
	js, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(js)
	for _, want := range []string{
		"revert:", "persist:", // ICONS registry entries
		"function revertOverride", "function persistToDefault", "function toastUndo",
		`iconBtn("revert"`, `iconBtn("persist"`,
		`/api/entry/delete`, `env: "default"`, // persist promotes into the default scope
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing %q — revert/persist wiring", want)
		}
	}

	css, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	cs := string(css)
	for _, want := range []string{".act-ico.revert", ".act-ico.persist", ".toast-undo"} {
		if !strings.Contains(cs, want) {
			t.Errorf("style.css missing %q — revert/persist styling", want)
		}
	}
}

// TestAssets_EntryTableColumns guards the entry table's shape: name, value,
// description, actions — and the header grips that resize the first two. The
// header, every row, and the add-row editor must all emit the same number of
// grid cells, or the actions drift into the description column. app.js has no
// JS harness, so presence checks are the regression guard.
func TestAssets_EntryTableColumns(t *testing.T) {
	js, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(js)
	for _, want := range []string{
		`resizableHead(tbl, "KEY", "name")`, `resizableHead(tbl, "VALUE", "val")`,
		`el("span", "th", "DESCRIPTION")`,
		"row.appendChild(descriptionCell(s));",
		"row.appendChild(descIn);", // add-row keeps the grid, with a description box
		"function applyColWidths", "setPointerCapture", `"byn.entryColWidths"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing %q — entry table columns", want)
		}
	}
	// The description is a column now, not a line under the name.
	for _, gone := range []string{"trow-desc", "trow-wrap", "descriptionLine"} {
		if strings.Contains(s, gone) {
			t.Errorf("app.js still references %q — description should be a column", gone)
		}
	}
	// Width storage can be blocked; a throw there must not break rendering.
	if !regexp.MustCompile(`try \{ localStorage\.setItem\(COL_WIDTHS_KEY`).MatchString(s) ||
		!regexp.MustCompile(`try \{ return JSON\.parse\(localStorage\.getItem\(COL_WIDTHS_KEY`).MatchString(s) {
		t.Error("column-width localStorage access must be wrapped in try/catch")
	}

	css, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	grid := regexp.MustCompile(`\.tbl-head, \.trow \{[^}]*grid-template-columns:\s*([^;]+);`).FindStringSubmatch(string(css))
	if grid == nil {
		t.Fatal("style.css: no grid-template-columns for .tbl-head, .trow")
	}
	// Split on top-level spaces only (minmax(...) and var(...) hold their own).
	tracks, depth, cur := []string{}, 0, ""
	for _, r := range strings.TrimSpace(grid[1]) {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ' ' && depth == 0:
			if cur != "" {
				tracks, cur = append(tracks, cur), ""
			}
			continue
		}
		cur += string(r)
	}
	tracks = append(tracks, cur)
	if len(tracks) != 5 {
		t.Fatalf("entry grid has %d tracks (%q), want 5: badge, name, value, description, actions", len(tracks), tracks)
	}
	if !strings.HasPrefix(tracks[1], "var(--col-name") || !strings.HasPrefix(tracks[2], "var(--col-val") {
		t.Errorf("name/value tracks must read the resize widths: %q", tracks)
	}
	// The actions track holds up to six 27px icons with 4px gaps; any less and
	// they overlap the description column.
	var actsPx int
	if _, err := fmt.Sscanf(tracks[4], "%dpx", &actsPx); err != nil || actsPx < 6*27+5*4 {
		t.Errorf("actions track = %q, want at least %dpx for six icons", tracks[4], 6*27+5*4)
	}
	for _, want := range []string{".col-grip", ".cell.desc", "body.col-resizing"} {
		if !strings.Contains(string(css), want) {
			t.Errorf("style.css missing %q — entry table columns", want)
		}
	}
}

// TestAssets_ErrorToastStackWired guards the persistent, Z-stacked error toasts:
// error toasts route to a stack (no auto-dismiss) with a per-card close, and the
// container + styles exist. app.js has no JS harness, so this presence check is
// the regression guard that the wiring is not silently lost.
func TestAssets_ErrorToastStackWired(t *testing.T) {
	js, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	for _, want := range []string{
		"function pushErrorToast", "function restackErrorToasts",
		"if (isErr) { pushErrorToast(msg); return; }", // toast() diverts errors to the stack
		`"toast-close"`,
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js missing %q — error-toast-stack wiring", want)
		}
	}

	html, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !strings.Contains(string(html), `id="toast-stack"`) {
		t.Errorf(`index.html missing id="toast-stack" — error-toast-stack container`)
	}

	css2, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	for _, want := range []string{".toast-stack", ".toast-err-card", ".toast-close"} {
		if !strings.Contains(string(css2), want) {
			t.Errorf("style.css missing %q — error-toast-stack styling", want)
		}
	}
}

// TestAssets_AnnotationEditingWired guards the description and notes editing
// in the entry table: the edit row carries a description box, the description
// cell edits in place, the notes list re-reads itself after a change, and note
// removal is confirmed inside the panel — a second openDialog there would
// replace the panel's own dialog.
func TestAssets_AnnotationEditingWired(t *testing.T) {
	js, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	s := string(js)
	for _, want := range []string{
		"const desc = descCell ? mountDescInput(s, descCell) : null;",
		"desc.changed()) await saveDescription(",
		"editDescription(s, cell)",
		"panel.replaceWith(buildNotesPanel(s, target, d, want));",
		"note-confirm",
		`"/api/annotation/history"`, "function renderNoteHistory", // history per note
		`id: n.id, text }`,                   // edit
		`"&removed=1"`, "show removed notes", // removed notes stay reachable
		`closest(".note-edit")`, // Esc cancels the editor, not the dialog
	} {
		if !strings.Contains(s, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	start := strings.Index(s, "function noteRow(")
	if start < 0 {
		t.Fatal("app.js: no noteRow")
	}
	body := s[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	if strings.Contains(body, "openDialog(") {
		t.Error("noteRow opens a dialog — it would replace the notes panel's own dialog")
	}

	// The note actions must be visible without hovering a table row: they
	// once reused .acts, which is opacity 0 outside .trow:hover.
	css, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatalf("read style.css: %v", err)
	}
	if !strings.Contains(string(css), ".note-acts {") || strings.Contains(body, `el("span", "acts")`) {
		t.Error("note actions must use .note-acts, not the hover-only .acts")
	}
}
