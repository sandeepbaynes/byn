package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// runWeb opens the local browser admin portal. The daemon hosts the
// portal; this command just resolves the configured URL and launches a
// browser at it.
//
// The portal API is gated by an owner-token. To avoid embedding that
// long-lived token in argv (visible to `ps`) or in URLs (visible in browser
// history), runWeb mints a one-time, 60s-TTL bootstrap token via the
// UID-gated Unix socket (web.bootstrap op) and passes ?auth=<bootstrap-token>
// to the browser. The SPA immediately exchanges the bootstrap token at
// POST /api/session/bootstrap for the persistent portal token, stores the
// persistent token in localStorage, and strips the ?auth= param via
// replaceState. A ps-captured bootstrap token is single-use and expires in 60s.
func runWeb(args []string) int {
	_ = args
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	cfg, err := config.Load(config.Path(dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if !cfg.UI.Enabled {
		fmt.Fprintln(os.Stderr, "Error: the web portal is disabled.")
		fmt.Fprintf(os.Stderr, "Set [ui] enabled = true in %s and restart the daemon.\n", config.Path(dir))
		return exitErr
	}

	// Best-effort daemon liveness check so we give an actionable hint
	// rather than launching a browser at a dead port.
	if err := newClient(dir, "").Call(ipc.OpStatus, ipc.StatusReq{}, &ipc.StatusResp{}); err != nil {
		fmt.Fprintln(os.Stderr, "Error: byn daemon is not running.")
		fmt.Fprintln(os.Stderr, "Run: byn start")
		return exitDaemonDown
	}

	// Mint a one-time bootstrap token via the UID-gated socket. The token is
	// single-use and expires in 60s, so a `ps` snapshot is of limited value
	// to an attacker. The persistent portal token never appears in argv or URLs.
	var bootResp ipc.WebBootstrapResp
	if err := newClient(dir, "").Call(ipc.OpWebBootstrap, ipc.WebBootstrapReq{}, &bootResp); err != nil {
		// Fallback: open without auth — browser will show the "not authorized"
		// notice and prompt the user to re-run `byn web`.
		fmt.Fprintf(os.Stderr, "Warning: could not mint bootstrap token (%v); opening without auth.\n", err)
	}

	base := fmt.Sprintf("http://localhost:%d", cfg.UI.Port)
	url := base
	if bootResp.Token != "" {
		url = base + "/?auth=" + bootResp.Token
	}
	fmt.Printf("byn web portal: %s\n", base) // print base URL (no token in stdout)
	if err := openBrowser(url); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open a browser automatically (%v).\n", err)
		// Print the base URL (without token) so the user sees a usable hint.
		// If they copy it manually they will hit the "not authorized" notice
		// and can re-run `byn web` to get an authorized URL.
		fmt.Fprintf(os.Stderr, "Open this URL manually: %s\n", base)
		fmt.Fprintln(os.Stderr, "(Re-run `byn web` to open an authorized session.)")
	}
	return exitOK
}

// openBrowserFn is the function used to launch the browser. Tests replace it
// with a no-op so they do not spawn a real browser during `go test`.
var openBrowserFn = openBrowserDefault

// openBrowser delegates to openBrowserFn (replaceable in tests).
func openBrowser(url string) error { return openBrowserFn(url) }

// openBrowserDefault launches the platform's default browser at url. The url is
// a loopback http://localhost:<port> built from a config int, and args
// are passed as a vector (no shell), so there is no injection surface.
func openBrowserDefault(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start() // #nosec G204 -- loopback localhost URL, no shell
	case "linux":
		return exec.Command("xdg-open", url).Start() // #nosec G204 -- loopback localhost URL, no shell
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}
