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

// Identifying the agent behind a caller.
//
// byn needs to recognise that two commands came from the same agent. It cannot
// use the caller: `byn put` exits at once. It cannot use the caller's parent
// either — an agent harness runs every command in its own short-lived shell, so
// that parent is dead by the next command. And it cannot simply walk a fixed
// number of hops: the first attempt took three, which reached the agent for a
// plain `bash -c` call and missed it entirely for one wrapped in `timeout`.
// The agent using byn measured it:
//
//	plain:   byn ← bash ← claude ← bash ← code
//	wrapped: byn ← bash ← timeout ← bash ← claude ← bash ← code
//
// The two chains overlap at the agent and nowhere shallower, and how deep that
// is depends on how the command happened to be invoked. Counting hops cannot
// work. What distinguishes those layers is what they ARE: shells and wrappers
// that exist only to launch the next thing. So byn walks past those and takes
// the first process that is doing something of its own. Both chains above
// resolve to the same claude, which is the answer.
//
// The hop cap is a safety bound on a pathological tree, not the rule.

// transientWrappers are process names that only ever exist to launch something
// else. Skipping them is what lets `byn put` under `timeout bash -c …` and a
// later plain `byn get` recognise each other.
//
// sudo is deliberately absent: it changes who you are, which is the opposite of
// transparent, and a boundary byn should stop at rather than see through.
var transientWrappers = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "fish": true, "ksh": true,
	"timeout": true, "env": true, "nice": true, "nohup": true, "xargs": true,
	"stdbuf": true, "setsid": true, "script": true,
}

// maxIdentityHops bounds the walk. Real trees are a handful deep; this only
// stops a cycle or a pathological tree from spinning the daemon.
const maxIdentityHops = 8

// callerIdentity returns the process byn treats as the agent behind a caller:
// the nearest ancestor that is not a transient wrapper.
func callerIdentity(pid int) procRef {
	if pid <= 0 {
		return procRef{}
	}
	seen := make(map[int]bool, maxIdentityHops)
	cur := pid
	for hops := 0; hops < maxIdentityHops; hops++ {
		comm, ppid := procInfo(cur)
		if ppid <= 1 || seen[ppid] {
			return procRef{}
		}
		seen[ppid] = true
		pcomm, _ := procInfo(ppid)
		cur = ppid
		if transientWrappers[pcomm] {
			continue // a shell or wrapper: keep walking
		}
		_ = comm
		start, ok := procStartTime(ppid)
		if !ok {
			return procRef{}
		}
		return procRef{PID: ppid, Start: start}
	}
	return procRef{}
}

// callerAncestry returns the identity to record for a caller, as a one-element
// chain. The slice shape is kept because records on disk carry one.
func callerAncestry(pid int) []procRef {
	id := callerIdentity(pid)
	if !id.ok() {
		return nil
	}
	return []procRef{id}
}

// callerOrigin returns the identity, kept for records written before byn stored
// a chain.
func callerOrigin(pid int) procRef { return callerIdentity(pid) }

// sharesAncestry reports whether a caller belongs to the same agent as the one
// that recorded want: their ancestor chains overlap.
//
// An empty want grants nothing, so a record byn could not pin down, or a
// platform that cannot supply process start times, simply asks for a credential.
func sharesAncestry(pid int, want []procRef) bool {
	if len(want) == 0 || pid <= 0 {
		return false
	}
	mine := callerIdentity(pid)
	for _, w := range want {
		if !w.ok() {
			continue
		}
		if mine == w {
			return true
		}
		// Also accept a caller running BENEATH the recorded identity: an agent
		// that spawns a helper which spawns byn is still that agent, and its
		// own nearest non-wrapper ancestor would be the helper.
		if isAncestor(w, pid) {
			return true
		}
	}
	return false
}

// isAncestor reports whether want is among pid's ancestors, within the hop cap.
func isAncestor(want procRef, pid int) bool {
	seen := make(map[int]bool, maxIdentityHops)
	cur := pid
	for hops := 0; hops < maxIdentityHops; hops++ {
		_, ppid := procInfo(cur)
		if ppid <= 1 || seen[ppid] {
			return false
		}
		seen[ppid] = true
		if ppid == want.PID {
			start, ok := procStartTime(ppid)
			return ok && start == want.Start
		}
		cur = ppid
	}
	return false
}
