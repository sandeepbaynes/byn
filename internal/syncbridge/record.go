// Package syncbridge turns vault entries into blobs a server can store without
// being able to read them, and back again.
//
// The server is treated as untrusted transport, not as a participant. It holds
// ciphertext, orders writes, and wakes devices; it never learns a value, a name,
// or a path. That framing decides the whole design: anything the server would
// need to understand in order to be useful is instead computed on a device.
package syncbridge

import (
	"encoding/json"
	"errors"
	"fmt"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// FormatVersion is the wire version of a sync record. It travels in the clear
// so a peer can refuse a record it does not understand rather than failing at
// the AEAD, which would be indistinguishable from tampering.
const FormatVersion = 1

// ErrUnsupportedVersion is returned for a record from a newer byn.
var ErrUnsupportedVersion = errors.New("syncbridge: record format is newer than this byn understands")

// Record is what the server stores. Everything the server can read is here at
// the top level; everything else is inside a sealed blob.
//
// Lamport and Device order writes across machines without a clock both sides
// trust. Wall time is kept only to break ties and to show a human when
// something changed — it is never the deciding factor, because two machines
// disagreeing about the time is normal and a clock that runs backwards should
// not silently win an edit.
type Record struct {
	Version int    `json:"v"`
	ID      string `json:"id"`
	VaultID string `json:"vault_id"`
	Lamport uint64 `json:"lamport"`
	Device  string `json:"device"`
	WallMS  int64  `json:"wall_ms"`
	Deleted bool   `json:"deleted,omitempty"`

	// Meta is the sealed name/kind of the entry. Sealed rather than plain
	// because a server holding every user's records is worth attacking, and the
	// names alone would say a great deal about what each vault is for.
	Meta []byte `json:"meta,omitempty"`
	// Value is the entry ciphertext exactly as it sits in the local vault. It is
	// not re-encrypted for transport: the row key already has no machine
	// binding, so the bytes on disk are the bytes another machine can open.
	Value []byte `json:"value,omitempty"`
	// AADVersion records which row-key scheme Value was sealed under, so a peer
	// opens it the same way the originating machine would.
	AADVersion int `json:"aad_version,omitempty"`
}

// meta is the sealed part of a record.
type meta struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Project string `json:"project,omitempty"`
	Env     string `json:"env,omitempty"`
}

// metaAAD binds sealed metadata to the record it belongs to, so a server cannot
// move one entry's name onto another entry's ciphertext.
func metaAAD(vaultID, recordID string) []byte {
	b := make([]byte, 0, len(vaultID)+1+len(recordID))
	b = append(b, vaultID...)
	b = append(b, 0x1F)
	b = append(b, recordID...)
	return b
}

// SealMeta encrypts an entry's identifying metadata for transport.
func SealMeta(metaKey []byte, vaultID, recordID, name, kind, project, env string) ([]byte, error) {
	plain, err := json.Marshal(meta{Name: name, Kind: kind, Project: project, Env: env})
	if err != nil {
		return nil, err
	}
	return vcrypto.EncryptWithAAD(metaKey, plain, metaAAD(vaultID, recordID))
}

// OpenMeta reverses SealMeta.
func OpenMeta(metaKey []byte, vaultID, recordID string, blob []byte) (name, kind, project, env string, err error) {
	plain, err := vcrypto.DecryptWithAAD(metaKey, blob, metaAAD(vaultID, recordID))
	if err != nil {
		return "", "", "", "", err
	}
	var m meta
	if err := json.Unmarshal(plain, &m); err != nil {
		return "", "", "", "", fmt.Errorf("syncbridge: metadata is malformed: %w", err)
	}
	return m.Name, m.Kind, m.Project, m.Env, nil
}

// Validate checks a record received from a server before anything acts on it.
//
// A server cannot forge content — the AEAD stops that — but it can serve a
// record that is merely well-formed nonsense, and every field below is used to
// decide something. Refusing early keeps a malformed record from reaching code
// that assumes it parsed.
func (r Record) Validate(expectVaultID string) error {
	if r.Version > FormatVersion {
		return fmt.Errorf("%w: record v%d, understood v%d", ErrUnsupportedVersion, r.Version, FormatVersion)
	}
	if r.ID == "" {
		return errors.New("syncbridge: record has no id")
	}
	if r.VaultID != expectVaultID {
		// A record for another vault landing here means the server mixed up
		// accounts, or is probing. Either way it must not be applied.
		return fmt.Errorf("syncbridge: record belongs to vault %q, not %q", r.VaultID, expectVaultID)
	}
	if !r.Deleted && len(r.Value) == 0 {
		return errors.New("syncbridge: live record carries no value")
	}
	return nil
}

// Newer reports whether r should replace other.
//
// Lamport counters decide, because they are the only ordering both machines
// actually agree on. Wall time breaks a tie, and the device id breaks a tie
// after that — not because the later device is more correct, but because every
// peer must reach the SAME answer without talking to the others. An arbitrary
// rule applied identically everywhere converges; a reasonable rule applied
// differently does not.
func (r Record) Newer(other Record) bool {
	if r.Lamport != other.Lamport {
		return r.Lamport > other.Lamport
	}
	if r.WallMS != other.WallMS {
		return r.WallMS > other.WallMS
	}
	return r.Device > other.Device
}
