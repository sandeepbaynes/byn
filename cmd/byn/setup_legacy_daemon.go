package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/daemon"
)

// legacyDaemonStopWait is how long setup waits for a SIGTERMed legacy daemon to
// close its vaults and exit. A clean shutdown checkpoints each vault's WAL, so
// it is worth waiting for rather than racing.
const legacyDaemonStopWait = 10 * time.Second

// legacyDaemonOps are the side effects stopLegacyDaemon needs, injected so the
// decision logic is testable without real processes, sockets or launchctl.
type legacyDaemonOps struct {
	readPID         func(dir string) (int, bool, error)
	alive           func(pid int) bool
	ownerUID        func(pid int) (int, error)
	terminate       func(pid int) error
	socketAnswers   func(path string) bool
	removeAutoStart func(home string, uid int) error
	now             func() time.Time
	sleep           func(time.Duration)
}

func defaultLegacyDaemonOps() legacyDaemonOps {
	return legacyDaemonOps{
		readPID:         daemonPID,
		alive:           processAlive,
		ownerUID:        processOwnerUID,
		terminate:       func(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) },
		socketAnswers:   unixSocketAnswers,
		removeAutoStart: removeLegacyAutoStart,
		now:             time.Now,
		sleep:           time.Sleep,
	}
}

// stopLegacyDaemon makes sure no per-user daemon is still serving legacyDir
// before setup copies it into the system data dir and deletes it.
//
// A daemon left running there is not harmless. It holds the vaults open, so the
// copy is a snapshot of live SQLite files and anything it writes afterwards
// lands in files the relocate then unlinks — data that exists only in that
// process and is lost when it exits. It also keeps the web portal port, so the
// _byn daemon's portal fails to bind and `byn web` opens a page served by the
// old daemon, listing vaults the new one has never heard of.
//
// The auto-start service goes first: a LaunchAgent with KeepAlive would respawn
// the daemon the moment it is stopped. Then the process named by the pidfile is
// SIGTERMed — only if it belongs to the owner, so a pid recycled by some other
// account is never signalled — and awaited. If anything still answers on the
// legacy socket after that, setup stops here rather than relocating under it.
func stopLegacyDaemon(legacyDir string, ownerUID int, ops legacyDaemonOps) error {
	if err := ops.removeAutoStart(filepath.Dir(legacyDir), ownerUID); err != nil {
		return fmt.Errorf("remove the per-user byn auto-start service: %w", err)
	}

	pid, ok, err := ops.readPID(legacyDir)
	if err != nil {
		return err
	}
	if ok && pid > 0 && ops.alive(pid) {
		if uid, uerr := ops.ownerUID(pid); uerr == nil && uid == ownerUID {
			if terr := ops.terminate(pid); terr != nil {
				return fmt.Errorf("stop the byn daemon running from %s (pid %d): %w", legacyDir, pid, terr)
			}
			deadline := ops.now().Add(legacyDaemonStopWait)
			for ops.alive(pid) {
				if ops.now().After(deadline) {
					return fmt.Errorf("the byn daemon running from %s (pid %d) did not exit within %s; "+
						"stop it (kill %d) and run setup again", legacyDir, pid, legacyDaemonStopWait, pid)
				}
				ops.sleep(50 * time.Millisecond)
			}
		}
	}

	sock := filepath.Join(legacyDir, daemon.SocketFilename)
	if ops.socketAnswers(sock) {
		return fmt.Errorf("a byn daemon is still answering on %s and no pidfile names it; "+
			"stop it (byn stop, as your normal user) and run setup again", sock)
	}
	return nil
}

// processOwnerUID reports the real UID a process runs as.
func processOwnerUID(pid int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-o", "uid=", "-p", strconv.Itoa(pid)).Output() // #nosec G204 -- fixed argv, pid is an int
	if err != nil {
		return 0, fmt.Errorf("ps pid %d: %w", pid, err)
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// unixSocketAnswers reports whether something accepts connections on path. A
// stale socket file left by a crashed daemon refuses, and reads as false.
func unixSocketAnswers(path string) bool {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// removeLegacyAutoStart unloads and deletes the per-user service `byn daemon
// install` writes (a LaunchAgent on macOS, a systemd --user unit on Linux).
// Once provisioned, the daemon is the _byn system service; the per-user one
// would start a second daemon at every login. Unloading is best-effort — the
// service may not be loaded — but a file that cannot be removed is an error,
// since it would bring the stray daemon back on next login.
func removeLegacyAutoStart(home string, uid int) error {
	var files []string
	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
		if _, err := os.Stat(plist); err != nil {
			return nil
		}
		_, _ = exec.Command("launchctl", "bootout", "gui/"+strconv.Itoa(uid)+"/"+launchdLabel).CombinedOutput() // #nosec G204 -- fixed argv
		files = []string{plist}
	case "linux":
		unit := filepath.Join(home, ".config", "systemd", "user", "byn.service")
		if _, err := os.Stat(unit); err != nil {
			return nil
		}
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			_, _ = exec.Command("systemctl", "--user", "--machine="+u.Username+"@", "disable", "--now", "byn.service").CombinedOutput() // #nosec G204 -- fixed argv
		}
		files = []string{unit, filepath.Join(home, ".config", "systemd", "user", "default.target.wants", "byn.service")}
	default:
		return nil
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
