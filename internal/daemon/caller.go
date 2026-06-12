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
	TTYDev  int32  // controlling terminal device number; 0 for portal callers (no socket peer)
	Comm    string // process name of the caller PID
	PComm   string // parent process name (who invoked it)
	Surface string // "socket" (cli/tui over the Unix socket) | "portal" (browser)
	// Session is the session token the caller presented in the envelope header.
	// Nil when no session was supplied (e.g. the unlock request that mints a
	// new session). Stored here so Task-2 gate helpers can read it from ctx
	// without each handler re-parsing the envelope.
	Session []byte
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

// callerSession returns the session token threaded through ctx by the dispatch
// layer (set from Envelope.Session at handleConn / Dispatch time). Returns nil
// when no session was presented. Task-2 gate helpers use this accessor so they
// never need to re-parse the envelope.
func callerSession(ctx context.Context) []byte {
	return callerFrom(ctx).Session
}

// socketCaller builds caller info for a Unix-socket peer (CLI/TUI),
// resolving the process name, invoking parent's name, and TTYDev.
// session is the token from Envelope.Session (nil when not yet minted).
func socketCaller(uid uint32, pid int, session []byte) callerInfo {
	comm, ppid := procInfo(pid)
	pcomm, _ := procInfo(ppid)
	ttyDev := peerTTYDev(pid)
	return callerInfo{UID: uid, PID: pid, TTYDev: ttyDev, Comm: comm, PComm: pcomm, Surface: "socket", Session: session}
}

// portalCaller builds caller info for an in-process portal request. The
// browser shares the daemon's process; the actor is the daemon's owner.
// session is the token from Envelope.Session (nil when not yet minted).
func (d *Daemon) portalCaller(session []byte) callerInfo {
	pid := os.Getpid()
	comm, _ := procInfo(pid)
	return callerInfo{UID: d.ownerUID, PID: pid, Comm: comm, Surface: "portal", Session: session}
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
