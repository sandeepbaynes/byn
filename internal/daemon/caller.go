package daemon

import (
	"context"
	"os"

	"github.com/sandeepbaynes/byn/internal/audit"
)

// callerInfo identifies who ran an operation, for the audit trail.
type callerInfo struct {
	UID     uint32
	PID     int
	Comm    string // process name of the caller PID
	PComm   string // parent process name (who invoked it)
	Surface string // "socket" (cli/tui over the Unix socket) | "portal" (browser)
}

type ctxKeyCaller struct{}

func withCaller(ctx context.Context, ci callerInfo) context.Context {
	return context.WithValue(ctx, ctxKeyCaller{}, ci)
}

func callerFrom(ctx context.Context) callerInfo {
	if ci, ok := ctx.Value(ctxKeyCaller{}).(callerInfo); ok {
		return ci
	}
	return callerInfo{}
}

// socketCaller builds caller info for a Unix-socket peer (CLI/TUI),
// resolving the process name and the invoking parent's name.
func socketCaller(uid uint32, pid int) callerInfo {
	comm, ppid := procInfo(pid)
	pcomm, _ := procInfo(ppid)
	return callerInfo{UID: uid, PID: pid, Comm: comm, PComm: pcomm, Surface: "socket"}
}

// portalCaller builds caller info for an in-process portal request. The
// browser shares the daemon's process; the actor is the daemon's owner.
func (d *Daemon) portalCaller() callerInfo {
	pid := os.Getpid()
	comm, _ := procInfo(pid)
	return callerInfo{UID: d.ownerUID, PID: pid, Comm: comm, Surface: "portal"}
}

// stampCaller fills an event's empty caller fields from ctx.
func stampCaller(ctx context.Context, ev *audit.Event) {
	ci := callerFrom(ctx)
	if ev.CallerUID == 0 {
		ev.CallerUID = ci.UID
	}
	if ev.CallerPID == 0 {
		ev.CallerPID = ci.PID
	}
	if ev.CallerComm == "" {
		ev.CallerComm = ci.Comm
	}
	if ev.CallerPComm == "" {
		ev.CallerPComm = ci.PComm
	}
	if ev.CallerSurface == "" {
		ev.CallerSurface = ci.Surface
	}
}
