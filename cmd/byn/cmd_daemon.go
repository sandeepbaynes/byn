package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/daemon"
	"github.com/sandeepbaynes/byn/internal/ipc"
)

// daemonConfigFor builds the daemon.Config for a data dir, folding in the
// optional ~/.byn/config file. A missing config file yields defaults; a
// malformed one is a hard error so the daemon fails fast with a clear
// message instead of silently ignoring settings.
func daemonConfigFor(dir string) (daemon.Config, error) {
	cfg, err := config.Load(config.Path(dir))
	if err != nil {
		return daemon.Config{}, err
	}
	return daemon.Config{
		Dir:         dir,
		Version:     version,
		IdleTimeout: time.Duration(cfg.Daemon.IdleTimeout),
		UIEnabled:   cfg.UI.Enabled,
		UIPort:      cfg.UI.Port,
		SessionTTL:  time.Duration(cfg.Security.SessionTTL),
		SessionIdle: time.Duration(cfg.Security.SessionIdle),
		Privsep:     cfg.PrivsepEnabled(),
	}, nil
}

func runDaemon(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: byn daemon {start|stop|restart|reload|status|install|uninstall} [--foreground]")
		return exitErr
	}
	switch args[0] {
	case "start":
		return runDaemonStart(args[1:])
	case "stop":
		return runDaemonStop(args[1:])
	case "restart":
		return runDaemonRestart(args[1:])
	case "reload":
		return runDaemonReload(args[1:])
	case "status":
		return runDaemonStatus(args[1:])
	case "install":
		return runDaemonInstall(args[1:])
	case "uninstall":
		return runDaemonUninstall(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "byn daemon: unknown subcommand %q\n", args[0])
		return exitErr
	}
}

// runDaemonRestart stops a running daemon (if any) and starts a fresh one
// — one command instead of stop + start. The new process picks up the
// current binary + config. Forwards flags (e.g. --foreground) to start.
func runDaemonRestart(args []string) int {
	// Under privsep, act on the _byn service (a SIGTERM stop+start is futile —
	// KeepAlive respawns it). The root-policy guard already required root here.
	if daemonProvisioned() {
		if err := restartServiceFn(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: restart the _byn service: %v\n", err)
			return exitErr
		}
		fmt.Fprintln(os.Stderr, "byn daemon restarted (the _byn service).")
		return exitOK
	}
	// Stop is best-effort: "no pidfile (already stopped)" returns exitOK,
	// so restart degrades to a plain start when nothing is running.
	if code := runDaemonStop(nil); code != exitOK {
		fmt.Fprintln(os.Stderr, "byn daemon: restart aborted — stop did not complete.")
		return code
	}
	// runDaemonStop only returns exitOK once the old process has exited,
	// and the daemon removes its socket + pidfile on shutdown, so start
	// finds a clean slate.
	return runDaemonStart(args)
}

// runDaemonReload signals a running daemon (SIGHUP) to re-read
// ~/.byn/config and apply the runtime-changeable settings (idle_timeout,
// web portal enable/port) WITHOUT restarting — open vaults stay unlocked.
// Use this for config tweaks; use `restart` to pick up a new binary.
func runDaemonReload(args []string) int {
	fs := flag.NewFlagSet("daemon reload", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	pid, ok, err := daemonPID(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "byn daemon: not running. Start it with: byn start")
		return exitErr
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: find process %d: %v\n", pid, err)
		return exitErr
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		fmt.Fprintf(os.Stderr, "Error: signal pid %d: %v\n", pid, err)
		return exitErr
	}
	fmt.Fprintf(os.Stderr, "byn daemon: reload signalled (pid %d). Applied changes are logged to %s.\n",
		pid, filepath.Join(dir, "daemon.log"))
	return exitOK
}

// daemonPID reads the daemon pidfile in dir. Returns (0, false, nil) when
// no pidfile exists (daemon not running); an error only for an unreadable
// or malformed pidfile.
func daemonPID(dir string) (int, bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, daemon.PIDFilename)) // #nosec G304 -- caller-controlled dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("read pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false, fmt.Errorf("pidfile %s has bad content: %w", filepath.Join(dir, daemon.PIDFilename), err)
	}
	return pid, true, nil
}

func runStatus(args []string) int {
	return runDaemonStatus(args)
}

func runDaemonStart(args []string) int {
	fs := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	foreground := fs.Bool("foreground", false, "run in foreground (do not detach)")
	allowRoot := fs.Bool("allow-root", false, "override the refusal to run as root (NOT recommended)")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if *foreground {
		return runDaemonForeground(dir, *allowRoot)
	}
	// Under privsep the daemon is the _byn launchd/systemd service — never spawn
	// it as the owner. Report status and delegate to the root path.
	if daemonProvisioned() {
		return startProvisionedDelegate(dir)
	}
	// Detached: re-exec ourselves with --foreground in a new session.
	return runDaemonDetached(dir, *allowRoot)
}

func runDaemonForeground(dir string, allowRoot bool) int {
	cfg, err := daemonConfigFor(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	cfg.AllowRoot = allowRoot
	d, err := daemon.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	fmt.Fprintf(os.Stderr, "byn daemon started: socket %s\n", d.SocketPath())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		if sig == syscall.SIGHUP {
			// Live config reload: re-read ~/.byn/config and apply the
			// runtime-changeable settings without dropping vault state.
			changes, err := d.Reload()
			switch {
			case err != nil:
				fmt.Fprintf(os.Stderr, "byn daemon: reload failed: %v\n", err)
			case len(changes) == 0:
				fmt.Fprintln(os.Stderr, "byn daemon: reload — no config changes")
			default:
				fmt.Fprintf(os.Stderr, "byn daemon: reloaded config: %s\n", strings.Join(changes, "; "))
			}
			continue
		}
		fmt.Fprintf(os.Stderr, "byn daemon: received %s, shutting down\n", sig)
		d.Shutdown(5 * time.Second)
		return exitOK
	}
	return exitOK
}

func runDaemonDetached(dir string, allowRoot bool) int {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: mkdir %s: %v\n", dir, err)
		return exitErr
	}
	// Check whether a daemon already responds on the socket.
	c := newClient(dir, "")
	if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &ipc.StatusResp{}); err == nil {
		fmt.Fprintf(os.Stderr, "byn daemon already running (socket %s).\n",
			activeSocketPath(dir))
		return exitOK
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: locate self: %v\n", err)
		return exitErr
	}

	logPath := filepath.Join(dir, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G302,G304 -- explicit 0600 + caller-controlled dir
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open log %s: %v\n", logPath, err)
		return exitErr
	}
	defer func() { _ = logFile.Close() }()

	// Forward --allow-root so the detached --foreground child inherits the
	// operator's explicit opt-in; otherwise it would re-trigger the root refusal.
	startArgs := []string{"daemon", "start", "--foreground"}
	if allowRoot {
		startArgs = append(startArgs, "--allow-root")
	}
	cmd := exec.Command(self, startArgs...) // #nosec G204 -- self-path, fixed args
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: fork daemon: %v\n", err)
		return exitErr
	}
	// Capture the PID before Release — Release zeros cmd.Process.Pid.
	childPID := cmd.Process.Pid
	// Detach from the child so it survives our exit.
	_ = cmd.Process.Release()

	// Wait briefly for the socket to appear so the user knows the
	// daemon is ready.
	if !waitForSocket(dir, 3*time.Second) {
		fmt.Fprintf(os.Stderr, "Warning: daemon process spawned (pid %d) but socket not ready after 3s.\n", childPID)
		fmt.Fprintf(os.Stderr, "Check %s for errors.\n", logPath)
		return exitErr
	}
	fmt.Fprintf(os.Stderr, "byn daemon started (pid %d, socket %s).\n",
		childPID, activeSocketPath(dir))
	return exitOK
}

func waitForSocket(dir string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	c := newClient(dir, "")
	for time.Now().Before(deadline) {
		if err := c.Call(ipc.OpStatus, ipc.StatusReq{}, &ipc.StatusResp{}); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func runDaemonStop(args []string) int {
	fs := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	// Under privsep, bootout the _byn service (a SIGTERM is futile — KeepAlive
	// respawns it). The root-policy guard already required root here.
	if daemonProvisioned() {
		if err := stopServiceFn(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: stop the _byn service: %v\n", err)
			return exitErr
		}
		fmt.Fprintln(os.Stderr, "byn daemon stopped (booted out the _byn service).")
		return exitOK
	}
	pid, ok, err := daemonPID(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "byn daemon: no pidfile found (already stopped?).")
		return exitOK
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: find process %d: %v\n", pid, err)
		return exitErr
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Error: SIGTERM pid %d: %v\n", pid, err)
		return exitErr
	}
	// Wait briefly for graceful exit.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := p.Signal(syscall.Signal(0)); err != nil {
			// Process is gone.
			fmt.Fprintln(os.Stderr, "byn daemon stopped.")
			return exitOK
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "Warning: daemon (pid %d) did not exit within 5s.\n", pid)
	return exitErr
}

func runDaemonStatus(args []string) int {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit StatusResp as JSON")
	if err := fs.Parse(args); err != nil {
		return exitErr
	}
	dir, err := defaultDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitErr
	}
	var resp ipc.StatusResp
	err = newClient(dir, "").Call(ipc.OpStatus, ipc.StatusReq{}, &resp)
	if rc := handleCallError(err); rc != exitOK {
		return rc
	}
	if *jsonOut {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return exitOK
	}
	fmt.Printf("daemon:  running (version %s, protocol %d..%d)\n",
		resp.Version, resp.ProtocolMin, resp.ProtocolMax)
	fmt.Printf("socket:  %s\n", resp.SocketPath)
	fmt.Printf("uptime:  %s\n", time.Since(resp.StartedAt).Round(time.Second))
	if len(resp.Vaults) == 0 {
		fmt.Println("vaults:  (none initialized)")
	} else {
		fmt.Println("vaults:")
		sessionlessUnlocked := false
		for _, v := range resp.Vaults {
			state := "locked"
			if !v.Locked {
				state = "unlocked"
			}
			line := fmt.Sprintf("  %-20s  %s", v.Name, state)
			if v.LastActive != nil {
				line += fmt.Sprintf("  (last active %s ago)",
					time.Since(*v.LastActive).Round(time.Second))
			}
			if !v.Locked {
				if v.SessionActive {
					if v.SessionExpiresAt != nil {
						line += fmt.Sprintf("  [session: active, expires in %s]",
							time.Until(*v.SessionExpiresAt).Round(time.Second))
					} else {
						line += "  [session: active]"
					}
				} else {
					line += dim("  [no session in this terminal — byn unlock to authorize reads]")
					sessionlessUnlocked = true
				}
			}
			fmt.Println(line)
		}
		if sessionlessUnlocked {
			fmt.Println(dim(`note: "unlocked" = the daemon holds the key (trusted exec runs); reading values still needs this terminal's session or the password.`))
		}
	}
	return exitOK
}
