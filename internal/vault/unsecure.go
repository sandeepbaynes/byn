package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Unsecure entries.
//
// Not everything a project keeps beside its secrets is one. A port, a region, a
// feature flag, the URL of a public API: these sit in the same .env file as the
// database password, and a vault that treats them all alike makes the harmless
// ones as hard to reach as the dangerous ones. The cost of that is paid by the
// approval queue — a person asked to authorize a read of LOG_LEVEL learns that
// the question is noise, and answers the next one without reading it.
//
// So an entry can be stored UNSECURE: the value column holds the bytes as they
// are, under no key. It can be read while the vault is locked, by anything that
// can reach byn at all, with no credential and no trusted .byn. That is the
// whole feature and also its whole risk, so the rules around it are narrow:
//
//   - Secure is the default everywhere. Nothing becomes unsecure unless the
//     call that writes it says so, each time. A write that does not say so
//     seals the value, even over an entry that was unsecure before — otherwise
//     a name created unsecure with a placeholder would silently take the real
//     credential in the clear when its owner later stored it.
//
//   - Saying "unsecure" as a value is written costs nothing extra: the caller
//     supplied the value, so nothing is disclosed to it. Turning an EXISTING
//     sealed value unsecure discloses something stored, to everyone, for good —
//     the daemon gates that on fresh proof of presence (see SetEnvVarsSecure's
//     callers).
//
//   - An unsecure value is still not anyone's to CHANGE. A sealed row cannot be
//     altered without the key; a bare plaintext row could be, by anything able
//     to write the database file — and a rewritten API_URL is injected into
//     the same process as the real credentials. So the row carries a MAC, and
//     byn checks it whenever it holds a key for the scope (see sealPlain).

// Tamper evidence for unsecure rows.
//
// The stored blob is  version(1) || HMAC-SHA-256(32) || value.  The MAC key is
// derived from the scope's authored key (K_auth), which is itself derived from
// the vault key and rides in every exec capability. That choice decides who
// can write an unsecure value and who can check one:
//
//   - WRITING needs K_auth: an unlocked vault, the master password, or a
//     trusted .byn's grant for the scope — exactly what a sealed write needs.
//     There is no such thing as an unsecure row with no MAC.
//
//   - CHECKING happens wherever K_auth is at hand: every read of an unlocked
//     vault, and a locked daemon's trusted exec, which is the case that
//     matters — the run that also carries secrets. A locked read with no grant
//     behind it (byn get, an untrusted .byn's run) holds no key and so is not
//     checked; that run carries nothing sealed, and whoever can rewrite the
//     vault file as this user can rewrite the project's own files too.
//
// The MAC binds the row's identity (scope ids, kind, name) as well as its
// value, so a row cannot be copied to another name or another env.
const (
	plainFormatV1  = 0x01
	plainHeaderLen = 1 + sha256.Size
	plainMACInfo   = "byn:plain-row-mac:v1"
)

// ErrPlainTampered means an unsecure row's MAC does not match its contents:
// the row was written, or altered, by something other than byn.
var ErrPlainTampered = errors.New("vault: unsecure value failed its integrity check")

// PlainKeys are the authored keys a caller without the vault key can offer for
// checking unsecure rows: Own for the scope that was named, Default for the
// project's default env, which the scope inherits from. Either may be empty.
type PlainKeys struct {
	Own     []byte
	Default []byte
}

func (s *Store) plainMAC(authoredKey []byte, projectID, envID int64, kind, name string, value []byte) ([]byte, error) {
	k, err := hkdfSubkey(authoredKey, plainMACInfo)
	if err != nil {
		return nil, err
	}
	defer zero(k)
	aad := s.entryAADV3(projectID, envID, kind, name)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(aad))) // #nosec G115 -- names are short
	m := hmac.New(sha256.New, k)
	m.Write(n[:])
	m.Write(aad)
	m.Write(value)
	return m.Sum(nil), nil
}

// sealPlain builds the stored blob for an unsecure value.
func (s *Store) sealPlain(authoredKey []byte, projectID, envID int64, kind, name string, value []byte) ([]byte, error) {
	if len(authoredKey) == 0 {
		return nil, ErrLocked
	}
	mac, err := s.plainMAC(authoredKey, projectID, envID, kind, name, value)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, plainHeaderLen+len(value))
	blob = append(blob, plainFormatV1)
	blob = append(blob, mac...)
	return append(blob, value...), nil
}

// openPlain returns the value an unsecure blob holds. With an authored key the
// MAC is checked; with none the value is returned unchecked, because there is
// nothing to check it with. A blob that is not in the format at all is
// tampering whether or not a key is at hand.
func (s *Store) openPlain(authoredKey []byte, projectID, envID int64, kind, name string, blob []byte) ([]byte, error) {
	if len(blob) < plainHeaderLen || blob[0] != plainFormatV1 {
		return nil, ErrPlainTampered
	}
	value := blob[plainHeaderLen:]
	if len(authoredKey) > 0 {
		want, err := s.plainMAC(authoredKey, projectID, envID, kind, name, value)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(want, blob[1:plainHeaderLen]) {
			return nil, ErrPlainTampered
		}
	}
	return append([]byte{}, value...), nil
}

// openPlainWithVaultKey is openPlain for a caller holding the vault key.
func (s *Store) openPlainWithVaultKey(vaultKey []byte, projectID, envID int64, kind, name string, blob []byte) ([]byte, error) {
	if len(vaultKey) == 0 {
		return s.openPlain(nil, projectID, envID, kind, name, blob)
	}
	ak, err := s.AuthoredKey(vaultKey, projectID, envID)
	if err != nil {
		return nil, err
	}
	defer zero(ak)
	return s.openPlain(ak, projectID, envID, kind, name, blob)
}

// sealPlainWithVaultKey is sealPlain for a caller holding the vault key.
func (s *Store) sealPlainWithVaultKey(vaultKey []byte, projectID, envID int64, kind, name string, value []byte) ([]byte, error) {
	if len(vaultKey) == 0 {
		return nil, ErrLocked
	}
	ak, err := s.AuthoredKey(vaultKey, projectID, envID)
	if err != nil {
		return nil, err
	}
	defer zero(ak)
	return s.sealPlain(ak, projectID, envID, kind, name, value)
}

// PutEnvVarUnsecure stores name in scope unsealed, on an unlocked vault.
// opt.CreateOnly is honoured exactly as PutEnvVar honours it.
func (s *Store) PutEnvVarUnsecure(ctx context.Context, scope Scope, name string, value []byte, opt PutOpt) error {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return ErrLocked
	}
	defer zero(vk)
	ak, err := s.authoredKeyForScope(ctx, vk, scope)
	if err != nil {
		return err
	}
	defer zero(ak)
	return s.PutEnvVarUnsecureWithKey(ctx, ak, scope, name, value, opt)
}

// PutEnvVarUnsecureWithKey is PutEnvVarUnsecure for a caller holding the
// scope's authored key rather than an unlocked vault — a grant's, or one
// captured with the master password — so it works while the vault is locked.
func (s *Store) PutEnvVarUnsecureWithKey(ctx context.Context, authoredKey []byte, scope Scope, name string, value []byte, opt PutOpt) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if err := validateEntryName(name); err != nil {
		return err
	}
	if len(value) > MaxValueLen {
		return fmt.Errorf("vault: value too large (%d > %d)", len(value), MaxValueLen)
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return err
	}
	stored, err := s.sealPlain(authoredKey, projectID, envID, kindAADEnvVar, name, value)
	if err != nil {
		return err
	}

	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if opt.CreateOnly {
		var exists int
		switch err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM entries WHERE project_id = ? AND env_id = ? AND name = ?`,
			projectID, envID, name).Scan(&exists); {
		case err == nil:
			return ErrExists
		case errors.Is(err, sql.ErrNoRows):
			// proceed
		default:
			return err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO entries (project_id, env_id, kind, name, value, aad_version, created_at, updated_at)
		 VALUES (?, ?, 'env_var', ?, ?, ?, ?, ?)
		 ON CONFLICT(project_id, env_id, name) DO UPDATE SET
			value=excluded.value, aad_version=excluded.aad_version, updated_at=excluded.updated_at`,
		projectID, envID, name, stored, aadVersionPlain, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// UnsecureEnvVar returns name's value when the entry a read in scope resolves
// to is unsecure, following the same inheritance GetEnvVar does. ok is false
// when there is no such entry or it is sealed — the two are deliberately not
// told apart here, because the caller's next step is the ordinary gated read
// either way, and that is where "not found" is decided.
//
// No credential and no unlock: that is what unsecure means. The value is
// checked against its MAC when the vault happens to be unlocked, and a row
// that fails is ErrPlainTampered.
func (s *Store) UnsecureEnvVar(ctx context.Context, scope Scope, name string) (Entry, bool, error) {
	return s.UnsecureEnvVarWithKeys(ctx, scope, name, PlainKeys{})
}

// UnsecureEnvVarWithKeys is UnsecureEnvVar for a caller that holds authored
// keys — a grant's — so the row can be checked while the vault is locked. An
// unlocked vault's own key is preferred when there is one.
func (s *Store) UnsecureEnvVarWithKeys(ctx context.Context, scope Scope, name string, keys PlainKeys) (Entry, bool, error) {
	if err := scope.Validate(); err != nil {
		return Entry{}, false, err
	}
	if err := validateEntryName(name); err != nil {
		return Entry{}, false, err
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return Entry{}, false, err
	}
	r, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil || !found || r.AADVersion != aadVersionPlain {
		return Entry{}, false, err
	}
	source := SourceScope
	ak := keys.Own
	if rowEnvID != envID {
		source = SourceDefault
		ak = keys.Default
	}
	var value []byte
	if vk := s.snapshotVaultKey(); vk != nil {
		value, err = s.openPlainWithVaultKey(vk, projectID, rowEnvID, kindAADEnvVar, name, r.Value)
		zero(vk)
	} else {
		value, err = s.openPlain(ak, projectID, rowEnvID, kindAADEnvVar, name, r.Value)
	}
	if err != nil {
		return Entry{}, false, &NameError{Name: name, Err: err}
	}
	return Entry{
		Name:      r.Name,
		Value:     value,
		Kind:      r.Kind,
		Source:    source,
		Unsecure:  true,
		CreatedAt: time.Unix(r.CreatedAt, 0).UTC(),
		UpdatedAt: time.Unix(r.UpdatedAt, 0).UTC(),
	}, true, nil
}

// SecureChange reports what SetEnvVarsSecure did with one name.
type SecureChange struct {
	Name string
	// Changed is false when the entry was already in the requested state.
	Changed bool
}

// ErrInheritedEntry means a name resolves through inheritance: the entry lives
// in the project's default env, not in the scope that was named. Changing what
// an entry IS has to be done where the entry is, or one env's decision would
// silently apply to every env that inherits from default.
var ErrInheritedEntry = errors.New("vault: entry is inherited from the default env")

// NameError names the entry an error is about, so a caller acting on several
// can say which one stopped it.
type NameError struct {
	Name string
	Err  error
}

func (e *NameError) Error() string { return fmt.Sprintf("%s: %v", e.Name, e.Err) }
func (e *NameError) Unwrap() error { return e.Err }

// SetEnvVarsSecure moves the named entries of scope between sealed and
// unsecure, all of them or none.
//
// It always needs the vault key, in both directions: making a value unsecure
// means opening it, and making it secure means sealing it. It acts only on
// entries that live in scope itself — a name that exists only by inheritance is
// refused with ErrInheritedEntry, and a name that does not exist with
// ErrNotFound, each wrapped in a NameError.
//
// Sealing gives the value the vault key's protection from here on. It does not
// take back what was readable before; a value that mattered should be rotated.
func (s *Store) SetEnvVarsSecure(ctx context.Context, scope Scope, names []string, secure bool) ([]SecureChange, error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return nil, ErrLocked
	}
	defer zero(vk)
	return s.SetEnvVarsSecureWithKey(ctx, vk, scope, names, secure)
}

// SetEnvVarsSecureWithKey is SetEnvVarsSecure for a caller that already holds
// the vault key — see UnwrapVaultKey — so a locked vault can be changed on the
// strength of a password without being unlocked.
func (s *Store) SetEnvVarsSecureWithKey(ctx context.Context, vaultKey []byte, scope Scope, names []string, secure bool) ([]SecureChange, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if len(vaultKey) == 0 {
		return nil, ErrLocked
	}
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := nowUnix()
	out := make([]SecureChange, 0, len(names))
	done := make(map[string]struct{}, len(names))
	for _, name := range names {
		if err := validateEntryName(name); err != nil {
			return nil, &NameError{Name: name, Err: err}
		}
		if _, dup := done[name]; dup {
			continue
		}
		done[name] = struct{}{}

		var stored []byte
		var ver int
		err := tx.QueryRowContext(ctx,
			`SELECT value, aad_version FROM entries
			 WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
			projectID, envID, name).Scan(&stored, &ver)
		if errors.Is(err, sql.ErrNoRows) {
			if s.inheritsEnvVar(ctx, tx, projectID, scope.Env, name) {
				return nil, &NameError{Name: name, Err: ErrInheritedEntry}
			}
			return nil, &NameError{Name: name, Err: ErrNotFound}
		}
		if err != nil {
			return nil, err
		}
		if (ver != aadVersionPlain) == secure {
			out = append(out, SecureChange{Name: name})
			continue
		}

		pt, err := s.openEntry(vaultKey, ver, projectID, envID, kindAADEnvVar, name, stored)
		if err != nil {
			return nil, &NameError{Name: name, Err: fmt.Errorf("vault: decrypt: %w", err)}
		}
		var newVer int
		var blob []byte
		if !secure {
			blob, err = s.sealPlainWithVaultKey(vaultKey, projectID, envID, kindAADEnvVar, name, pt)
			zero(pt)
			if err != nil {
				return nil, &NameError{Name: name, Err: err}
			}
			newVer = aadVersionPlain
		} else {
			blob, err = s.sealEntry(vaultKey, projectID, envID, kindAADEnvVar, name, pt)
			zero(pt)
			if err != nil {
				return nil, &NameError{Name: name, Err: fmt.Errorf("vault: encrypt: %w", err)}
			}
			newVer = currentAADVersion
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE entries SET value = ?, aad_version = ?, updated_at = ?
			 WHERE project_id = ? AND env_id = ? AND kind = 'env_var' AND name = ?`,
			blob, newVer, now, projectID, envID, name); err != nil {
			return nil, err
		}
		out = append(out, SecureChange{Name: name, Changed: true})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// inheritsEnvVar reports whether name, absent from a non-default env, exists in
// the project's default env.
func (s *Store) inheritsEnvVar(ctx context.Context, tx *sql.Tx, projectID int64, scopeEnv, name string) bool {
	if scopeEnv == DefaultEnvName {
		return false
	}
	var one int
	err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM entries e JOIN envs v ON v.id = e.env_id
		 WHERE e.project_id = ? AND v.name = ? AND e.kind = 'env_var' AND e.name = ?`,
		projectID, DefaultEnvName, name).Scan(&one)
	return err == nil
}

// IsUnsecureEntry reports whether scope's OWN entry for name is unsecure.
// Exact, not merged with default: it answers what a write here would replace.
func (s *Store) IsUnsecureEntry(ctx context.Context, scope Scope, name string) (bool, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return false, err
	}
	r, found, err := s.fetchEntry(ctx, projectID, envID, kindAADEnvVar, name)
	if err != nil || !found {
		return false, err
	}
	return r.AADVersion == aadVersionPlain, nil
}
