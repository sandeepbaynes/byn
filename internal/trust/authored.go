package trust

import "sort"

// Self-authored variables.
//
// Adding a name to [exec] env is normally a widening: the project is asking to
// receive a secret it could not receive before, so a human decides. That rule
// costs nothing when the secret already existed — but it stops the loop an
// agent actually runs, which is: create a value, wire it into .byn, start the
// service. Nothing is disclosed there. The caller supplied the value; making it
// ask permission to read back what it just wrote is friction with no security
// to show for it, and it was the single most common reason byn blocked an
// otherwise autonomous run.
//
// So byn separates the two cases by asking who authored the value:
//
//   - Created BEFORE this project was trusted — a pre-existing secret. Exposing
//     it to the project's commands for the first time is a real widening and
//     still needs a human.
//   - Created AFTER the grant, never overwritten since, by the same origin that
//     is now running the command — the caller demonstrably knows it already.
//     Auto-granted, and audited.
//
// Only the third condition needs storing, because the vault already knows when
// each entry was created and whether it has been written again. This file
// carries that record. It is MAC-bound alongside the rest of the grant, so an
// entry cannot be edited into existence after the fact.

// AuthoredGrant records that a variable was created through byn by a caller
// whose origin process is identified by (OriginPID, OriginStart).
type AuthoredGrant struct {
	// Name is the variable that was created.
	Name string `json:"name"`
	// OriginPID and OriginStart identify the creating caller's PARENT — the
	// agent or shell that ran `byn put`, not the byn process itself, which has
	// exited long before the value is ever used. OriginStart is the kernel's
	// start-time tick count for that PID; pairing the two makes the identity
	// immune to PID reuse, so a later process cannot inherit the authorship of
	// one that has died.
	OriginPID   int    `json:"origin_pid"`
	OriginStart uint64 `json:"origin_start"`
	// AtUnixNano is when byn recorded the authorship, for display and pruning.
	AtUnixNano int64 `json:"at_unix_nano"`
}

// AuthoredBy returns the authorship entry for name, and whether one exists.
func (r *Record) AuthoredBy(name string) (AuthoredGrant, bool) {
	for _, a := range r.SelfAuthored {
		if a.Name == name {
			return a, true
		}
	}
	return AuthoredGrant{}, false
}

// WithAuthored returns list with g merged in, replacing any existing entry for
// the same name and keeping the result sorted by name.
//
// Re-creating a name (delete then put, both authorized) legitimately re-dates
// its authorship, so the newest entry wins rather than the first.
func WithAuthored(list []AuthoredGrant, g AuthoredGrant) []AuthoredGrant {
	out := make([]AuthoredGrant, 0, len(list)+1)
	for _, a := range list {
		if a.Name != g.Name {
			out = append(out, a)
		}
	}
	out = append(out, g)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
