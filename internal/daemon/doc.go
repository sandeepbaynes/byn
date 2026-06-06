// Package daemon is the byn background process.
//
// Owns:
//   - a Unix domain socket (mode 0600) for IPC with the CLI
//   - the encrypted vault (internal/vault.Store)
//   - the in-memory unlock state and key
//   - the rate limiter for failed unlocks (internal/auth)
//
// Does not own (yet):
//   - the OS service unit (launchd/systemd) — that's Slice 1.3
//   - idle re-lock timers — Slice 1.3
//   - biometric unlock — Slice 1.3
//   - the local web UI — Phase 2
//
// Connection model: one Unix socket; each accepted connection
// services one envelope and closes. Simpler than a multiplexed
// long-lived connection and matches how the CLI works (one command,
// one IPC round-trip).
package daemon
