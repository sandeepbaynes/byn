package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/auth"
	"github.com/sandeepbaynes/byn/internal/config"
	"github.com/sandeepbaynes/byn/internal/ui"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Default file names inside the daemon's data directory (the root).
const (
	SocketFilename = "daemon.sock"
	PIDFilename    = "daemon.pid"
)

// Config configures a Daemon.
type Config struct {
	// Dir is the daemon's data root: holds daemon.sock, daemon.pid,
	// auth-state.json, daemon.log, and the vaults/ subtree.
	Dir string

	// Version is the daemon binary version, surfaced via OpStatus.
	Version string

	// OwnerUID, if non-zero, is the only UID allowed to connect.
	// Default (zero) uses the process's effective UID.
	OwnerUID uint32

	// Clock is the time source for the auth rate limiter. Tests inject
	// a fake clock. Nil ⇒ wall clock.
	Clock auth.Clock

	// IdleTimeout re-locks an unlocked vault after this much inactivity.
	// Zero (or negative) disables the idle re-lock janitor entirely.
	// Wired from config.Daemon.IdleTimeout at daemon start.
	IdleTimeout time.Duration

	// UIEnabled starts the embedded browser admin portal on loopback.
	// UIPort is the port to bind (0 ⇒ ui default 2967). Wired from
	// config.UI at daemon start.
	UIEnabled bool
	UIPort    int
}

// vaultEntry is the daemon's handle on one open vault.
type vaultEntry struct {
	name       string
	store      *vault.Store
	auditor    *audit.Logger
	lastActive atomic.Int64 // unix nanos; 0 if never touched
}

// touch updates lastActive to the current wall-clock time.
func (e *vaultEntry) touch() {
	e.lastActive.Store(time.Now().UTC().UnixNano())
}

// Daemon owns the socket listener and the map of open vaults.
type Daemon struct {
	cfg Config

	socketPath  string
	pidPath     string
	limiterPath string

	ownerUID uint32

	startedAt time.Time

	// idleNanos is the live idle re-lock timeout in nanoseconds; 0 disables
	// auto-relock (see lockIdleVaults / idleTickInterval). Atomic so the
	// janitor goroutine reads it while Reload writes it. Read via
	// idleTimeoutDur.
	idleNanos atomic.Int64

	// janitorOnce guards a single idle-janitor goroutine. Start launches it
	// when idle is enabled at boot; Reload launches it lazily when a config
	// change enables idle after boot. Once started it runs until Shutdown,
	// reading idleNanos live (a no-op tick while disabled).
	janitorOnce sync.Once

	// uiMu guards uiSrv across Start, Shutdown, UIPort and Reload (which can
	// stop/start the portal at runtime).
	uiMu sync.Mutex
	// uiSrv is the embedded browser portal, started in Start when
	// cfg.UIEnabled and stopped in Shutdown. nil when disabled.
	uiSrv *ui.Server

	// pkChallenges holds in-flight WebAuthn ceremony challenges (register +
	// auth) keyed by a one-time ceremony id, with a short TTL. Server-side
	// challenge storage is mandatory — the browser response binds to it.
	pkChallenges *passkeyChallenges

	// reloadMu serializes Reload so two concurrent SIGHUPs can't interleave
	// portal restarts.
	reloadMu sync.Mutex

	limiter *auth.RateLimiter

	// vaults holds every Store the daemon has opened in this process
	// lifetime. Entries persist until Shutdown — locking a vault zeros
	// the in-memory key (via vault.Store.Lock) but keeps the *Store so
	// the next unlock doesn't need to reopen the DB.
	vaultsMu sync.RWMutex
	vaults   map[string]*vaultEntry

	// listener/conn state
	listenerMu sync.Mutex
	listener   *net.UnixListener

	// shutdown coordination
	shutdownOnce sync.Once
	closeCh      chan struct{}
	wg           sync.WaitGroup

	// rootCtx is the daemon-scoped context derived from Start's ctx.
	// Cancelled on Shutdown. Per-request handlers derive child
	// contexts from it so in-flight SQLite + audit operations
	// observe shutdown without separate goroutine plumbing.
	rootCtx    context.Context
	rootCancel context.CancelFunc
}

// New constructs a Daemon. It does NOT bind the socket; call Start.
func New(cfg Config) (*Daemon, error) {
	if cfg.Dir == "" {
		return nil, errors.New("daemon: empty dir")
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.OwnerUID == 0 {
		euid := os.Geteuid()
		if euid < 0 {
			return nil, fmt.Errorf("daemon: geteuid returned negative %d", euid)
		}
		cfg.OwnerUID = uint32(euid) //nolint:gosec // bounded by check above
	}

	d := &Daemon{
		cfg:          cfg,
		socketPath:   filepath.Join(cfg.Dir, SocketFilename),
		pidPath:      filepath.Join(cfg.Dir, PIDFilename),
		limiterPath:  filepath.Join(cfg.Dir, auth.RateLimiterFile),
		ownerUID:     cfg.OwnerUID,
		closeCh:      make(chan struct{}),
		vaults:       make(map[string]*vaultEntry),
		pkChallenges: newPasskeyChallenges(),
	}
	d.idleNanos.Store(int64(cfg.IdleTimeout))
	d.limiter = auth.NewRateLimiter(d.limiterPath)
	if cfg.Clock != nil {
		d.limiter.SetClock(cfg.Clock)
	}
	return d, nil
}

// Start binds the socket, writes the pidfile, and serves connections
// until ctx is cancelled or Shutdown is called.
//
// Stale pidfiles (PID no longer exists) are replaced. If the pidfile
// points at a running process, Start returns an already-running
// error.
//
// Start opens the "default" vault eagerly if it exists, so the
// first-command latency on a normal install stays low. Other vaults
// open on first IPC lookup.
func (d *Daemon) Start(ctx context.Context) error {
	if err := os.MkdirAll(d.cfg.Dir, 0o700); err != nil {
		return fmt.Errorf("daemon: mkdir %s: %w", d.cfg.Dir, err)
	}
	if err := d.handlePidFile(); err != nil {
		return err
	}
	if err := d.bind(); err != nil {
		_ = os.Remove(d.pidPath)
		return err
	}
	d.startedAt = time.Now().UTC()
	// Daemon-scoped context. Derived from the caller's ctx so a
	// SIGTERM-cancelled `daemon start --foreground` ctx propagates
	// to every in-flight handler; cancelled on Shutdown so detached
	// builds can terminate in-flight SQLite + audit ops cleanly.
	d.rootCtx, d.rootCancel = context.WithCancel(ctx)

	// Eager-open the default vault. Missing is fine (init will create
	// it); a corruption-style failure is fatal so the user sees it.
	if _, err := d.openVault(ctx, vault.DefaultVaultName); err != nil &&
		!errors.Is(err, vault.ErrNotInit) {
		_ = d.cleanupListener()
		_ = os.Remove(d.pidPath)
		return fmt.Errorf("daemon: open default vault: %w", err)
	}

	d.wg.Add(1)
	go d.serve(ctx)

	// Idle re-lock janitor: launch only when configured at boot. A later
	// `daemon reload` that enables idle-timeout starts it lazily.
	if d.idleTimeoutDur() > 0 {
		d.ensureJanitor()
	}

	// Embedded browser portal. Optional: a bind failure (e.g. port in
	// use) disables the portal but never blocks the daemon — the CLI and
	// TUI keep working over the socket.
	if d.cfg.UIEnabled {
		d.uiMu.Lock()
		if err := d.startUILocked(d.cfg.UIPort); err != nil {
			fmt.Fprintf(os.Stderr, "byn: web portal disabled: %v\n", err)
		}
		d.uiMu.Unlock()
	}
	return nil
}

// UIPort reports the bound portal port, or 0 when the portal isn't
// running.
func (d *Daemon) UIPort() int {
	d.uiMu.Lock()
	defer d.uiMu.Unlock()
	if d.uiSrv == nil {
		return 0
	}
	return d.uiSrv.Port()
}

// startUILocked constructs, binds and serves the embedded portal on the
// given port (<=0 ⇒ ui default). The caller MUST hold uiMu. The Serve
// goroutine is registered with the waitgroup so Shutdown drains it. A bind
// error is returned and leaves uiSrv nil.
func (d *Daemon) startUILocked(port int) error {
	select {
	case <-d.closeCh:
		return errors.New("daemon: shutting down")
	default:
	}
	srv := ui.New(d, ui.Config{Port: port})
	if err := srv.Listen(); err != nil {
		return err
	}
	d.uiSrv = srv
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		_ = srv.Serve()
	}()
	return nil
}

// SocketPath returns the absolute path to the bound Unix socket.
func (d *Daemon) SocketPath() string { return d.socketPath }

// Shutdown drains in-flight connections and releases socket + pidfile.
// All open vaults are closed (which zeros their in-memory keys).
// Idempotent.
func (d *Daemon) Shutdown(timeout time.Duration) {
	d.shutdownOnce.Do(func() {
		close(d.closeCh)
		d.uiMu.Lock()
		if d.uiSrv != nil {
			_ = d.uiSrv.Close()
			d.uiSrv = nil
		}
		d.uiMu.Unlock()
		if d.rootCancel != nil {
			// Cancel the daemon-scoped context so in-flight SQLite +
			// audit operations observe shutdown immediately. The
			// listener cleanup + drain below still bounds total time.
			d.rootCancel()
		}
		_ = d.cleanupListener()
		done := make(chan struct{})
		go func() { d.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(timeout):
		}
		d.vaultsMu.Lock()
		for name, e := range d.vaults {
			_ = e.store.Close()
			delete(d.vaults, name)
		}
		d.vaultsMu.Unlock()
		_ = os.Remove(d.pidPath)
	})
}

// Wait blocks until the daemon stops serving.
func (d *Daemon) Wait() {
	d.wg.Wait()
}

// handlerCtx returns a context for use inside an op handler. Tied to
// the daemon's lifecycle so SQLite + audit calls observe shutdown.
// Falls back to context.Background when no root is set (tests that
// drive dispatch directly without calling Start).
func (d *Daemon) handlerCtx() context.Context {
	if d.rootCtx != nil {
		return d.rootCtx
	}
	return context.Background()
}

// ---- idle re-lock -------------------------------------------------------

// idleTimeoutDur returns the live idle re-lock timeout. 0 (or negative)
// means auto-relock is disabled.
func (d *Daemon) idleTimeoutDur() time.Duration {
	return time.Duration(d.idleNanos.Load())
}

// ensureJanitor starts the idle-janitor goroutine exactly once for the
// daemon's lifetime. Safe to call from Start (idle enabled at boot) and
// from Reload (idle enabled later). A no-op once shutting down.
func (d *Daemon) ensureJanitor() {
	d.janitorOnce.Do(func() {
		select {
		case <-d.closeCh:
			return // shutting down; don't add to the waitgroup
		default:
		}
		d.wg.Add(1)
		go d.runIdleJanitor()
	})
}

// runIdleJanitor periodically re-locks vaults that have been idle longer
// than the live idle timeout. Exits on Shutdown (closeCh). It owns one
// waitgroup slot. The tick interval is recomputed each round so a
// `daemon reload` that changes idle_timeout takes effect without a restart.
func (d *Daemon) runIdleJanitor() {
	defer d.wg.Done()
	t := time.NewTicker(d.idleTickInterval())
	defer t.Stop()
	for {
		select {
		case <-d.closeCh:
			return
		case <-t.C:
			d.lockIdleVaults(time.Now().UTC())
			t.Reset(d.idleTickInterval())
		}
	}
}

// idleTickInterval is how often the janitor checks for idle vaults. It is
// capped at 30s so a long idle window doesn't delay shutdown, and floored
// at 100ms so a tiny (mis)configured timeout can't spin hot. A disabled
// timeout (<=0) still ticks lazily at 30s so a reload that re-enables it is
// noticed promptly.
func (d *Daemon) idleTickInterval() time.Duration {
	to := d.idleTimeoutDur()
	switch {
	case to <= 0:
		return 30 * time.Second
	case to > 30*time.Second:
		return 30 * time.Second
	case to < 100*time.Millisecond:
		return 100 * time.Millisecond
	default:
		return to
	}
}

// lockIdleVaults locks every currently-unlocked vault whose last activity
// is older than idleTimeout, zeroing its in-memory key, and returns the
// number locked. A non-positive idleTimeout disables auto-relock (returns
// 0). now is a parameter so the decision is deterministically testable.
func (d *Daemon) lockIdleVaults(now time.Time) int {
	to := d.idleTimeoutDur()
	if to <= 0 {
		return 0
	}
	d.vaultsMu.RLock()
	entries := make([]*vaultEntry, 0, len(d.vaults))
	for _, e := range d.vaults {
		entries = append(entries, e)
	}
	d.vaultsMu.RUnlock()

	locked := 0
	for _, e := range entries {
		if e.store.IsLocked() {
			continue
		}
		last := e.lastActive.Load()
		if last == 0 {
			continue // no activity baseline yet — don't auto-lock
		}
		if now.Sub(time.Unix(0, last)) >= to {
			e.store.Lock()
			locked++
		}
	}
	return locked
}

// ---- live config reload -------------------------------------------------

// Reload re-reads ~/.byn/config and applies the settings that can change at
// runtime without dropping daemon state: the idle re-lock timeout and the
// embedded browser portal (enable / disable / port). Open vaults stay open
// and unlocked across a reload. It returns a human-readable list of what
// changed (empty when nothing did). The data dir, owner UID and binary
// version are fixed at start and are never reloaded — those need a restart.
func (d *Daemon) Reload() ([]string, error) {
	cfg, err := config.Load(config.Path(d.cfg.Dir))
	if err != nil {
		return nil, err
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()

	var changes []string

	// Idle re-lock timeout.
	newIdle := time.Duration(cfg.Daemon.IdleTimeout)
	if old := d.idleTimeoutDur(); old != newIdle {
		d.idleNanos.Store(int64(newIdle))
		changes = append(changes, fmt.Sprintf("idle_timeout %s → %s", idleStr(old), idleStr(newIdle)))
		if newIdle > 0 {
			d.ensureJanitor()
		}
	}

	// Browser portal.
	changes = append(changes, d.reloadUI(cfg.UI.Enabled, cfg.UI.Port)...)
	return changes, nil
}

// reloadUI brings the portal into the desired (enabled, port) state,
// starting / stopping / rebinding as needed, and returns a change note (or
// nil when already in the desired state). A bind failure is reported as a
// change note rather than a hard error so one bad portal port never wedges
// the rest of the reload.
func (d *Daemon) reloadUI(enabled bool, port int) []string {
	norm := port
	if norm <= 0 {
		norm = config.DefaultUIPort
	}
	d.uiMu.Lock()
	defer d.uiMu.Unlock()

	running := d.uiSrv != nil
	runningPort := 0
	if running {
		runningPort = d.uiSrv.Port()
	}

	switch {
	case !enabled && !running:
		return nil
	case !enabled && running:
		_ = d.uiSrv.Close()
		d.uiSrv = nil
		return []string{fmt.Sprintf("web portal disabled (was :%d)", runningPort)}
	case enabled && running && runningPort == norm:
		return nil
	case enabled && running: // port changed
		_ = d.uiSrv.Close()
		d.uiSrv = nil
		if err := d.startUILocked(norm); err != nil {
			return []string{fmt.Sprintf("web portal :%d → :%d failed: %v", runningPort, norm, err)}
		}
		return []string{fmt.Sprintf("web portal :%d → :%d", runningPort, norm)}
	default: // enabled && !running
		if err := d.startUILocked(norm); err != nil {
			return []string{fmt.Sprintf("web portal enable on :%d failed: %v", norm, err)}
		}
		return []string{fmt.Sprintf("web portal enabled on :%d", d.uiSrv.Port())}
	}
}

// idleStr renders an idle-timeout duration for a change note, mapping a
// non-positive duration to "disabled".
func idleStr(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// ---- multi-vault helpers ------------------------------------------------

// lookupVault returns the in-memory entry for name, or nil if the
// vault hasn't been opened in this process yet. Does NOT touch disk.
func (d *Daemon) lookupVault(name string) *vaultEntry {
	d.vaultsMu.RLock()
	defer d.vaultsMu.RUnlock()
	return d.vaults[name]
}

// openVault opens (lazily) the named vault and constructs its audit
// Logger. If already open, returns the existing entry. Wraps
// vault.Open's error semantics — callers can errors.Is against
// vault.ErrNotInit / ErrFingerprintMismatch.
func (d *Daemon) openVault(ctx context.Context, name string) (*vaultEntry, error) {
	if e := d.lookupVault(name); e != nil {
		return e, nil
	}
	d.vaultsMu.Lock()
	defer d.vaultsMu.Unlock()
	if e, ok := d.vaults[name]; ok {
		return e, nil
	}
	st, err := vault.Open(ctx, d.cfg.Dir, name)
	if err != nil {
		return nil, err
	}
	logger, err := audit.New(ctx, d.cfg.Dir, st.VaultID(), name, st)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("daemon: audit logger for %s: %w", name, err)
	}
	e := &vaultEntry{name: name, store: st, auditor: logger}
	d.vaults[name] = e
	return e, nil
}

// adoptVault registers an already-open Store (e.g., one just returned
// by vault.Init) under name. Replaces any existing entry, closing the
// old Store first.
func (d *Daemon) adoptVault(ctx context.Context, name string, st *vault.Store) (*vaultEntry, error) {
	d.vaultsMu.Lock()
	defer d.vaultsMu.Unlock()
	if old, ok := d.vaults[name]; ok {
		_ = old.store.Close()
	}
	logger, err := audit.New(ctx, d.cfg.Dir, st.VaultID(), name, st)
	if err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("daemon: audit logger for %s: %w", name, err)
	}
	e := &vaultEntry{name: name, store: st, auditor: logger}
	d.vaults[name] = e
	return e, nil
}

// removeVault drops the named entry, closing its Store (which zeroes any
// in-memory key). Used by the vault.delete handler before the on-disk
// secure wipe. Idempotent.
func (d *Daemon) removeVault(name string) {
	d.vaultsMu.Lock()
	defer d.vaultsMu.Unlock()
	if e, ok := d.vaults[name]; ok {
		_ = e.store.Close()
		delete(d.vaults, name)
	}
}

// allVaultsOnDisk lists every vault that has a directory under
// <root>/vaults/, regardless of whether it's currently open in this
// process. Used by OpVaultList.
func (d *Daemon) allVaultsOnDisk() ([]string, error) {
	vaultsRoot := filepath.Join(d.cfg.Dir, vault.VaultsSubdir)
	entries, err := os.ReadDir(vaultsRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Names are validated at create time; skip anything that
		// doesn't pass validation now (handles stray cruft).
		if err := vault.ValidateVaultName(e.Name()); err != nil {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// ---- internal -----------------------------------------------------------

func (d *Daemon) handlePidFile() error {
	if data, err := os.ReadFile(d.pidPath); err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil && pid > 0 {
			if processAlive(pid) {
				return fmt.Errorf("daemon: another daemon appears to be running (pid %d at %s)", pid, d.pidPath)
			}
		}
		_ = os.Remove(d.pidPath)
	}
	pid := os.Getpid()
	return os.WriteFile(d.pidPath, []byte(fmt.Sprintf("%d\n", pid)), 0o600)
}

func (d *Daemon) bind() error {
	if _, err := os.Stat(d.socketPath); err == nil {
		if c, err := net.Dial("unix", d.socketPath); err == nil {
			_ = c.Close()
			return fmt.Errorf("daemon: socket %s is already in use", d.socketPath)
		}
		_ = os.Remove(d.socketPath)
	}
	prev := syscall.Umask(0o077)
	defer syscall.Umask(prev)

	addr, err := net.ResolveUnixAddr("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("daemon: resolve %s: %w", d.socketPath, err)
	}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("daemon: listen %s: %w", d.socketPath, err)
	}
	if err := os.Chmod(d.socketPath, 0o600); err != nil {
		_ = l.Close()
		return fmt.Errorf("daemon: chmod socket: %w", err)
	}
	d.listenerMu.Lock()
	d.listener = l
	d.listenerMu.Unlock()
	return nil
}

func (d *Daemon) cleanupListener() error {
	d.listenerMu.Lock()
	l := d.listener
	d.listener = nil
	d.listenerMu.Unlock()
	var err error
	if l != nil {
		err = l.Close()
	}
	_ = os.Remove(d.socketPath)
	return err
}

func (d *Daemon) serve(ctx context.Context) {
	defer d.wg.Done()
	go func() {
		select {
		case <-ctx.Done():
			d.Shutdown(2 * time.Second)
		case <-d.closeCh:
		}
	}()

	for {
		d.listenerMu.Lock()
		l := d.listener
		d.listenerMu.Unlock()
		if l == nil {
			return
		}
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-d.closeCh:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		d.wg.Add(1)
		go func(c net.Conn) {
			defer d.wg.Done()
			defer closeAcceptedConn(c)
			d.handleConn(c)
		}(conn)
	}
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	return true
}
