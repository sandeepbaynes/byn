package ui

import (
	"embed"
	"net/http"
)

// assetsFS holds the embedded single-page app (HTML/JS/CSS). Served at /
// (the shell) and /static/ (assets).
//
//go:embed assets
var assetsFS embed.FS

// handleIndex serves the SPA shell at the root and 404s everything else
// that didn't match a more specific route.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
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
