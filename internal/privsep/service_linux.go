//go:build linux

package privsep

import (
	"fmt"

	"github.com/sandeepbaynes/byn/internal/paths"
)

// systemUnitPath is the canonical location of the byn daemon's systemd system
// unit. /etc/systemd/system is the admin-managed unit dir (overrides vendor
// units), which is correct for a service installed by `byn setup` rather than a
// distro package.
const systemUnitPath = "/etc/systemd/system/byn.service"

// runtimeSocketDir is the systemd RuntimeDirectory (relative to /run) holding the
// owner-reachable daemon socket. systemd creates /run/byn as _byn:_byn 0755 and
// tears it down when the unit stops. It is kept distinct from the _byn:_byn 0700
// StateDirectory so the socket's parent can stay traversable to the owner while
// the vault state dir is not. Literal here because it is a systemd-relative name,
// not a filesystem path the rest of byn resolves (paths.SocketPath() is the full
// /run/byn/daemon.sock).
const runtimeSocketDir = "byn"

// systemdUnit returns the /etc/systemd/system/byn.service content for the byn
// daemon. execPath is the absolute path to the installed byn binary (e.g.
// /usr/local/bin/byn); ExecStart runs `<execPath> daemon start`.
//
// The unit runs the daemon as the _byn service user with an aggressively
// hardened sandbox, but deliberately leaves NoNewPrivileges OFF — see the
// load-bearing comment in the generated [Service] section.
func systemdUnit(execPath string) string {
	return "[Unit]\n" +
		"Description=byn secrets vault daemon\n" +
		"Documentation=https://github.com/sandeepbaynes/byn\n" +
		"After=network.target\n" +
		"\n" +
		"[Service]\n" +
		"Type=simple\n" +
		"User=" + DaemonUser + "\n" +
		// --foreground is load-bearing: systemd Type=simple supervises the started
		// process directly, so the daemon must stay in the foreground and NOT
		// self-detach. Without it `daemon start` forks a detached daemon and the
		// tracked process exits, which systemd reads as the service dying →
		// Restart=on-failure respawns endlessly against the detached daemon's pidfile.
		"ExecStart=" + execPath + " daemon start --foreground\n" +
		"Restart=on-failure\n" +
		"\n" +
		"# StateDirectory makes systemd create and own " + paths.SystemDataDir() + " as\n" +
		"# " + DaemonUser + ":" + DaemonUser + " 0700 before the daemon starts — the vault tree the\n" +
		"# separate-UID daemon reads. RuntimeDirectory does the same for /run/byn,\n" +
		"# the owner-traversable parent of the peercred-gated socket.\n" +
		"StateDirectory=byn\n" +
		"StateDirectoryMode=0700\n" +
		"RuntimeDirectory=" + runtimeSocketDir + "\n" +
		"\n" +
		"# --- Hardening -------------------------------------------------------\n" +
		"# Read-only the whole filesystem except the two paths the daemon writes.\n" +
		"ProtectSystem=strict\n" +
		"ReadWritePaths=" + paths.SystemDataDir() + " /run/byn\n" +
		"# Hide other processes — the daemon never needs to see them, and an\n" +
		"# invisible /proc denies an attacker reconnaissance from inside the unit.\n" +
		"ProtectProc=invisible\n" +
		"ProcSubset=pid\n" +
		"# The daemon only ever talks over the AF_UNIX socket; deny every other\n" +
		"# address family so a compromise cannot open network sockets.\n" +
		"RestrictAddressFamilies=AF_UNIX\n" +
		"SystemCallFilter=@system-service\n" +
		"# No W^X memory — block mapping a page writable then executable.\n" +
		"MemoryDenyWriteExecute=yes\n" +
		"\n" +
		"# NoNewPrivileges MUST stay no. The NU-5 exec path drops the spawned\n" +
		"# child to " + ExecUser + " via a root-owned helper carrying cap_setuid file\n" +
		"# capabilities. Setting NoNewPrivileges=yes makes the kernel ignore (strip)\n" +
		"# those file caps on execve, so the helper could no longer setuid and the\n" +
		"# child would run as " + DaemonUser + " instead of " + ExecUser + " — collapsing the\n" +
		"# privsep boundary the whole feature exists to create. Do not flip this.\n" +
		"NoNewPrivileges=no\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
}

// sysusersConfPath is the canonical path systemd-sysusers reads declarative user
// definitions from. Reuses the drop-in dir constant from provision_linux.go.
const sysusersConfPath = sysusersDropDir + "/byn.conf"

// applySysusers writes the declarative _byn / _byn-exec definitions to the
// canonical /usr/lib/sysusers.d/byn.conf and runs systemd-sysusers to create the
// accounts. Idempotent and image-friendly (systemd-sysusers is a no-op when the
// users already exist). Reuses sysusersConf() from the NU-5 provisioning so the
// account definitions have a single source of truth.
func applySysusers(run runner) error {
	conf := sysusersConf()
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%s' %q > %q", conf, sysusersConfPath)); err != nil {
		return fmt.Errorf("write sysusers.d: %w", err)
	}
	if err := run("systemd-sysusers", sysusersConfPath); err != nil {
		return fmt.Errorf("apply sysusers (%s): %w", sysusersConfPath, err)
	}
	return nil
}

// InstallService provisions the service users via sysusers.d and installs +
// enables the byn daemon systemd unit. execPath is the absolute path to the
// installed byn binary (the unit's ExecStart). All side effects go through the
// injected runner so the sequence is unit-testable without root or systemd.
//
// Sequence: write sysusers.d → systemd-sysusers → write the unit →
// systemctl daemon-reload → systemctl enable --now byn.service.
func InstallService(run runner, execPath string) error {
	if err := applySysusers(run); err != nil {
		return err
	}
	unit := systemdUnit(execPath)
	if err := run("sh", "-c",
		fmt.Sprintf("printf '%%s' %q > %q", unit, systemUnitPath)); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := run("systemctl", "enable", "--now", "byn.service"); err != nil {
		return fmt.Errorf("enable byn.service: %w", err)
	}
	return nil
}

// UninstallService disables + stops the byn daemon unit and removes the unit
// file. It deliberately leaves the sysusers.d definitions, the _byn/_byn-exec
// accounts, and the vault state under the system data dir in place — removing
// users + state is a separate `--purge` concern handled by `byn setup
// --uninstall` (Task 10). All side effects go through the injected runner.
//
// Sequence: systemctl disable --now byn.service → remove the unit →
// systemctl daemon-reload.
func UninstallService(run runner) error {
	if err := run("systemctl", "disable", "--now", "byn.service"); err != nil {
		return fmt.Errorf("disable byn.service: %w", err)
	}
	if err := run("rm", "-f", systemUnitPath); err != nil {
		return fmt.Errorf("remove unit: %w", err)
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	return nil
}
