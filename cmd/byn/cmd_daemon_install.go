package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// `byn daemon install` registers the daemon as a user-level auto-start service
// (launchd LaunchAgent on macOS, a systemd --user unit on Linux) so it comes up
// on login. `byn daemon uninstall` reverses it. Single-owner, self-hosted — no
// root, no system-wide install.

const launchdLabel = "com.sandeepbaynes.byn"

// serviceSpec is the platform-resolved auto-start service: where its file goes,
// its contents, and the (best-effort) commands to (un)load it.
type serviceSpec struct {
	manager string     // human label: "launchd" / "systemd user"
	path    string     // install path for the plist/unit
	content string     // file contents
	load    [][]string // best-effort commands to load + enable
	unload  [][]string // best-effort commands to disable + unload
}

func runDaemonInstall(args []string) int {
	_ = args
	spec, err := daemonServiceSpec()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	if err := os.MkdirAll(filepath.Dir(spec.path), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	if err := os.WriteFile(spec.path, []byte(spec.content), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "%s write %s: %v\n", boldRed("Error:"), spec.path, err)
		return exitErr
	}
	fmt.Printf("Wrote %s service: %s\n", spec.manager, spec.path)

	// Loading is best-effort: even if it fails (no GUI session, already loaded,
	// CI), the file alone makes the daemon start on next login.
	loaded := true
	for _, argv := range spec.load {
		if _, lerr := exec.Command(argv[0], argv[1:]...).CombinedOutput(); lerr != nil { // #nosec G204 -- fixed argv, no user input
			loaded = false
		}
	}
	if loaded {
		fmt.Println("byn daemon installed and started — it will auto-start on login.")
	} else {
		fmt.Println("byn daemon service installed — it will start on next login.")
	}
	fmt.Printf("Uninstall with: %s\n", cyan("byn daemon uninstall"))
	return exitOK
}

func runDaemonUninstall(args []string) int {
	_ = args
	spec, err := daemonServiceSpec()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %v\n", boldRed("Error:"), err)
		return exitErr
	}
	for _, argv := range spec.unload {
		_, _ = exec.Command(argv[0], argv[1:]...).CombinedOutput() // #nosec G204 -- fixed argv; best-effort
	}
	if rerr := os.Remove(spec.path); rerr != nil && !os.IsNotExist(rerr) {
		fmt.Fprintf(os.Stderr, "%s remove %s: %v\n", boldRed("Error:"), spec.path, rerr)
		return exitErr
	}
	fmt.Printf("byn daemon auto-start removed (%s).\n", spec.path)
	return exitOK
}

// daemonServiceSpec resolves the platform service: the running byn binary, the
// install path, contents, and (un)load commands. Errors on unsupported OSes.
func daemonServiceSpec() (serviceSpec, error) {
	bin, err := os.Executable()
	if err != nil {
		return serviceSpec{}, fmt.Errorf("resolve byn binary: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(bin); rerr == nil {
		bin = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return serviceSpec{}, err
	}
	bynDir := os.Getenv("BYN_DIR") // "" ⇒ the service uses the default ~/.byn

	switch runtime.GOOS {
	case "darwin":
		path := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
		return serviceSpec{
			manager: "launchd",
			path:    path,
			content: launchdPlist(bin, bynDir),
			load:    [][]string{{"launchctl", "unload", path}, {"launchctl", "load", "-w", path}},
			unload:  [][]string{{"launchctl", "unload", path}},
		}, nil
	case "linux":
		path := filepath.Join(home, ".config", "systemd", "user", "byn.service")
		return serviceSpec{
			manager: "systemd user",
			path:    path,
			content: systemdUnit(bin, bynDir),
			load:    [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", "byn.service"}},
			unload:  [][]string{{"systemctl", "--user", "disable", "--now", "byn.service"}},
		}, nil
	default:
		return serviceSpec{}, fmt.Errorf("daemon install supports macOS (launchd) and Linux (systemd user), not %s", runtime.GOOS)
	}
}

// launchdPlist renders a macOS LaunchAgent that runs the daemon in foreground.
func launchdPlist(bin, bynDir string) string {
	env := ""
	if bynDir != "" {
		env = fmt.Sprintf("  <key>EnvironmentVariables</key>\n  <dict>\n    <key>BYN_DIR</key>\n    <string>%s</string>\n  </dict>\n", bynDir)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>start</string>
    <string>--foreground</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
%s</dict>
</plist>
`, launchdLabel, bin, env)
}

// systemdUnit renders a systemd --user unit that runs the daemon in foreground.
func systemdUnit(bin, bynDir string) string {
	env := ""
	if bynDir != "" {
		env = fmt.Sprintf("Environment=BYN_DIR=%s\n", bynDir)
	}
	return fmt.Sprintf(`[Unit]
Description=byn secrets daemon
After=default.target

[Service]
Type=simple
ExecStart=%s start --foreground
%sRestart=on-failure

[Install]
WantedBy=default.target
`, bin, env)
}
