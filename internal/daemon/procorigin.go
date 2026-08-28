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
	callerOriginFn   = callerOrigin
	callerAncestryFn = callerAncestry
	sharesAncestryFn = sharesAncestry
)

// procRef identifies one process unambiguously across PID reuse.
type procRef struct {
	PID   int
	Start uint64
}

// ok reports whether the reference is usable. A zero PID means no parent was
// found; a zero start time means the platform could not supply one, and byn
// will not grant anything on an identity it cannot pin down.
func (p procRef) ok() bool { return p.PID > 1 && p.Start != 0 }

// originDepth is how far above a caller byn looks for an identity, and it is
// the whole difficulty of this file.
//
// The first version recorded only the immediate parent, on the reasoning that
// `byn put` exits at once so the parent is the thing still around to run byn
// again. That is true and useless: an agent harness runs each command in its
// own short-lived shell, so the parent of one `byn put` has died by the time
// the matching `byn exec` runs, and the exemption expired at the end of every
// tool call — precisely the workflow it exists for. A live run caught it; every
// test had done its put and its exec inside one shell.
//
// So byn records a short chain instead, and two callers count as the same agent
// when their chains overlap. The depth is what draws the line. At 2-3 hops the
// chain reaches the agent process that spawned both shells and stops there. Go
// deeper and it reaches the terminal, the editor, the desktop session — and
// then every process on the machine shares an ancestor and the check means
// nothing.
//
// Three is chosen against the real shape: byn → shell → agent. It is a
// heuristic, and it fails in the safe direction — an unrecognised caller is
// asked for a credential, never handed one. The residual is that a process
// spawned very close to the agent in the tree can match; what it gains by that
// is limited to values the agent itself created unattended, never a secret that
// was already in the vault.
const originDepth = 3

// callerAncestry returns the chain of processes above a caller, nearest first,
// bounded by originDepth. pid 1 is never included: everything descends from it.
func callerAncestry(pid int) []procRef {
	if pid <= 0 {
		return nil
	}
	var out []procRef
	seen := make(map[int]bool, originDepth)
	cur := pid
	for len(out) < originDepth {
		_, ppid := procInfo(cur)
		if ppid <= 1 || seen[ppid] {
			break
		}
		seen[ppid] = true
		start, ok := procStartTime(ppid)
		if !ok {
			break
		}
		out = append(out, procRef{PID: ppid, Start: start})
		cur = ppid
	}
	return out
}

// callerOrigin returns the nearest usable ancestor, kept for records written
// before byn stored a chain.
func callerOrigin(pid int) procRef {
	chain := callerAncestry(pid)
	if len(chain) == 0 {
		return procRef{}
	}
	return chain[0]
}

// sharesAncestry reports whether a caller belongs to the same agent as the one
// that recorded want: their ancestor chains overlap.
//
// An empty want grants nothing, so a record byn could not pin down, or a
// platform that cannot supply process start times, simply asks for a credential.
func sharesAncestry(pid int, want []procRef) bool {
	if len(want) == 0 || pid <= 0 {
		return false
	}
	mine := callerAncestry(pid)
	for _, w := range want {
		if !w.ok() {
			continue
		}
		for _, m := range mine {
			if m == w {
				return true
			}
		}
	}
	return false
}
