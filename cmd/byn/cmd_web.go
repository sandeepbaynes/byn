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
	if err := newClient(dir).Call(ipc.OpStatus, ipc.StatusReq{}, &ipc.StatusResp{}); err != nil {
		fmt.Fprintln(os.Stderr, "Error: byn daemon is not running.")
		fmt.Fprintln(os.Stderr, "Run: byn daemon start")
		return exitDaemonDown
	}

	url := fmt.Sprintf("http://localhost:%d", cfg.UI.Port)
	fmt.Printf("byn web portal: %s\n", url)
	if err := openBrowser(url); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open a browser automatically (%v).\n", err)
		fmt.Fprintf(os.Stderr, "Open this URL manually: %s\n", url)
	}
	return exitOK
}

// openBrowser launches the platform's default browser at url. The url is
// a loopback http://localhost:<port> built from a config int, and args
// are passed as a vector (no shell), so there is no injection surface.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start() // #nosec G204 -- loopback localhost URL, no shell
	case "linux":
		return exec.Command("xdg-open", url).Start() // #nosec G204 -- loopback localhost URL, no shell
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
}
