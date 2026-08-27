package daemon

// Process origin — the identity byn uses to tell "the same agent" from "someone
// else on this machine".
//
// A `byn put` and the `byn exec` that later uses the value are two separate,
// short-lived processes, so neither one's PID identifies the agent. What is
// stable across both is their common ancestor: Claude Code, an editor, a shell,
// a CI runner. byn records the creating caller's PARENT as the origin, and a
// later command counts as the same origin when that process is still one of its
// own ancestors.
//
// A session id would be simpler, but does not survive the trip: agent harnesses
// commonly start each tool call in a fresh session, which gives the two calls
// different session ids while their parent stays the same. The ancestor walk is
// what actually holds.
//
// PIDs are reused, so an origin is (pid, start-time) — the kernel's start-time
// counter for that exact process. A new process landing on a recycled PID has a
// different start time and inherits nothing.

// Seams. The tests that drive the daemon end to end run every request from one
// process, so they cannot produce two genuinely different origins; these let
// them. The functions themselves are exercised against the real process tree in
// procorigin_test.go, so stubbing here never hides a broken walk.
var (
	callerOriginFn = callerOrigin
	sharesOriginFn = sharesOrigin
)

// maxAncestorHops bounds the walk from a caller up towards pid 1. Real trees are
// a handful deep; the bound just means a cycle or a pathological tree cannot
// spin the daemon.
const maxAncestorHops = 32

// procRef identifies one process unambiguously across PID reuse.
type procRef struct {
	PID   int
	Start uint64
}

// ok reports whether the reference is usable. A zero PID means no parent was
// found; a zero start time means the platform could not supply one, and byn
// will not grant anything on an identity it cannot pin down.
func (p procRef) ok() bool { return p.PID > 1 && p.Start != 0 }

// callerOrigin returns the origin to record for a caller: its parent process.
//
// The parent, not the caller itself: `byn put` exits immediately, so recording
// it would produce an identity that can never match again. The parent is the
// thing that ran byn and is still around to run it a second time.
func callerOrigin(pid int) procRef {
	if pid <= 0 {
		return procRef{}
	}
	_, ppid := procInfo(pid)
	if ppid <= 1 {
		return procRef{} // orphaned or reparented to init: no usable origin
	}
	start, ok := procStartTime(ppid)
	if !ok {
		return procRef{}
	}
	return procRef{PID: ppid, Start: start}
}

// sharesOrigin reports whether want is the caller itself or one of its
// ancestors — i.e. whether this command is running under the same agent, shell,
// or runner that created the value.
//
// A process in another terminal, another editor window, or a background service
// does not have that ancestor and so does not inherit the grant, which is the
// whole point: the exemption follows the caller who supplied the value, not the
// machine.
func sharesOrigin(pid int, want procRef) bool {
	if !want.ok() || pid <= 0 {
		return false
	}
	seen := make(map[int]bool, maxAncestorHops)
	for cur, hops := pid, 0; cur > 1 && hops < maxAncestorHops; hops++ {
		if seen[cur] {
			return false // cycle: a tree we cannot trust, so grant nothing
		}
		seen[cur] = true
		if cur == want.PID {
			// Same PID: confirm it is the same PROCESS and not a reuse.
			start, ok := procStartTime(cur)
			return ok && start == want.Start
		}
		_, ppid := procInfo(cur)
		cur = ppid
	}
	return false
}
