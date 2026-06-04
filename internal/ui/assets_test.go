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
