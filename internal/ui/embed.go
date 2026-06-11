package ui

import (
	"embed"
	"net/http"
	"strings"
)

// assetsFS holds the embedded single-page app (HTML/JS/CSS). Served at /
// (the shell) and /static/ (assets).
//
//go:embed assets
var assetsFS embed.FS

// handleIndex is the catch-all handler registered at "/". It serves the SPA
// shell (index.html) for any GET request that reaches it, implementing the
// history-API fallback so deep-linked routes like /settings or
// /studio?path=... return the SPA and let the JS router render the correct
// view on reload.
//
// Security: /api/* routes are registered before this handler so the mux
// dispatches them first; they never fall through here. We additionally reject
// any path that starts with "/api/" as a safety belt, so an API miss is always
// a 404, never a silently-served HTML page. Real static assets (/static/…) are
// also registered before this handler and served from the embedded FS.
// handleFavicon serves the embedded SVG favicon at /favicon.svg.
// It is registered before the catch-all handleIndex so the SPA fallback
// never swallows browser favicon requests.
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	data, err := assetsFS.ReadFile("assets/favicon.svg")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(data)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Only GET requests are candidates for the SPA fallback.
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	// Refuse to serve index.html for /api/* paths — those must stay 404.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "missing index asset")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}
