//go:build !linux && !darwin

package daemon

// procStartTime has no supported lookup on this platform. Returning ok=false
// means byn cannot pin a process identity here, so self-authored grants never
// apply and every widening goes to a human — the safe direction.
func procStartTime(_ int) (uint64, bool) { return 0, false }
