// Package vault is the encrypted secrets store.
//
// The vault is a single SQLite database. Secret names and timestamps
// live in plaintext (so the index is queryable while locked); secret
// values are encrypted via internal/vault/crypto under a 32-byte
// vault key.
//
// The vault key itself is wrapped at rest by Argon2id(password) and
// (in later slices) sealed by a hardware-backed wrapping key via
// internal/hwkey. The wrapped key blob lives outside the SQLite file
// (path: vaultDir/wrapped.key) so that backing up the SQLite file
// alone without the wrap key buys an attacker nothing.
//
// Concurrency model: a single Store instance is safe for concurrent
// use from multiple goroutines. SQLite is opened in WAL mode so
// readers and a single writer can coexist without long lock holds.
//
// This package does NOT manage the password prompt, the unlock
// lifecycle, or the network/IPC layer — those live in internal/auth
// and internal/daemon respectively. The Store exposes Lock/Unlock
// in terms of "set the working vault key" and "clear it".
package vault
