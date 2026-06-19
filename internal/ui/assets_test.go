package ui

import (
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
