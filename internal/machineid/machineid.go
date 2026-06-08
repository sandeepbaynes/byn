// Package machineid reads a stable, per-machine identifier used to key the
// trust store's machine-fingerprint MAC.
//
// It is NOT secret — any process on the host can read the same source — so it
// binds a trust record to THIS machine (rejecting records minted on another
// machine and copied in), but it does not defend against a same-UID agent on
// this machine (that is the vault-key MAC's job). The two layers compose.
package machineid

import (
	"crypto/sha256"
	"errors"
)

// ErrUnavailable means no stable machine identifier could be read on this host.
var ErrUnavailable = errors.New("machineid: no stable machine identifier available")

const idDomain = "byn:machine-id:v1"

// ID returns a stable 32-byte identifier for THIS machine: SHA-256 over a
// platform hardware/OS machine id (macOS IOPlatformUUID, Linux
// /etc/machine-id), domain-separated so it is never confused with another hash.
// It is stable across reboots and differs across machines.
func ID() ([]byte, error) {
	raw, err := platformID()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(idDomain))
	h.Write([]byte{0x1f})
	h.Write([]byte(raw))
	return h.Sum(nil), nil
}
