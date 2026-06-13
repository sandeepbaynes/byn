package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Passkey is a stored WebAuthn credential for the vault. All fields are
// non-secret — security rests on possession of the authenticator plus user
// verification. Used for portal session auth (slice A-auth.1); the PRF
// cold-unlock fields (a wrapped second copy of the vault key) arrive in
// A-auth.2 and are NOT modelled here yet.
type Passkey struct {
	CredentialID   []byte    // WebAuthn credential ID (raw bytes)
	PublicKey      []byte    // COSE-encoded public key
	SignCount      uint32    // authenticator signature counter (clone detection)
	AAGUID         []byte    // authenticator model id (may be all-zero)
	Transports     string    // comma-joined transports hint (e.g. "internal,hybrid")
	Label          string    // human label, e.g. "MacBook Touch ID"
	BackupEligible bool      // WebAuthn BE flag — immutable per credential; MUST round-trip or ValidateLogin rejects the assertion
	BackupState    bool      // WebAuthn BS flag — may change over time
	CreatedAt      time.Time // enrollment time
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// AddPasskey stores a newly-enrolled credential. Returns an error if a
// credential with the same ID already exists (UNIQUE constraint) or if the
// required fields are missing.
func (s *Store) AddPasskey(ctx context.Context, pk Passkey) error {
	if len(pk.CredentialID) == 0 || len(pk.PublicKey) == 0 {
		return fmt.Errorf("vault: passkey requires credential_id and public_key")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO passkey (credential_id, public_key, sign_count, aaguid, transports, label, backup_eligible, backup_state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pk.CredentialID, pk.PublicKey, int64(pk.SignCount), pk.AAGUID, pk.Transports, pk.Label,
		b2i(pk.BackupEligible), b2i(pk.BackupState), nowUnix()); err != nil {
		return fmt.Errorf("vault: add passkey: %w", err)
	}
	return nil
}

// Passkeys lists every enrolled credential, newest first.
func (s *Store) Passkeys(ctx context.Context) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id, public_key, sign_count, aaguid, transports, label, backup_eligible, backup_state, created_at
		 FROM passkey ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Passkey
	for rows.Next() {
		pk, serr := scanPasskey(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, pk)
	}
	return out, rows.Err()
}

// PasskeyByCredentialID returns the credential with the given ID, or
// ErrNotFound when no such credential is enrolled.
func (s *Store) PasskeyByCredentialID(ctx context.Context, credID []byte) (Passkey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT credential_id, public_key, sign_count, aaguid, transports, label, backup_eligible, backup_state, created_at
		 FROM passkey WHERE credential_id = ?`, credID)
	pk, err := scanPasskey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Passkey{}, ErrNotFound
	}
	return pk, err
}

// UpdatePasskeySignCount records the authenticator's monotonic counter after a
// successful assertion (the clone-detection input). Returns ErrNotFound when
// the credential is absent.
func (s *Store) UpdatePasskeySignCount(ctx context.Context, credID []byte, count uint32) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE passkey SET sign_count = ? WHERE credential_id = ?`, int64(count), credID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes a credential (revoke). Returns whether a row was
// removed; a no-op delete (absent credential) is not an error.
func (s *Store) DeletePasskey(ctx context.Context, credID []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkey WHERE credential_id = ?`, credID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ClearPasskeyEnrollments removes every passkey credential and its PRF-unlock
// record from the vault, in a single transaction. It is the "drop passkeys"
// operation a cross-source `byn migrate --from` import performs (spec §6.2 D1):
// an imported vault brings DATA only, never the previous machine's enrolled
// authenticators — the owner must re-enroll passkeys on this machine.
//
// Passkey enrollments are NOT separate files; they live in this vault's
// `passkey` and `passkey_unlock` tables, so dropping them is a DELETE, not a
// file removal. The vault key is never touched (the password wrap is the floor)
// and no entries/audit data are affected — only the two passkey tables. Safe on
// a locked Store (these tables hold no plaintext). Idempotent: clearing an
// already-empty pair of tables is a no-op success.
//
// Order matters: passkey_unlock has a foreign key into passkey, so it is
// emptied first (the FK would also cascade, but deleting the child explicitly
// keeps the statement order obvious and FK-pragma-independent).
func (s *Store) ClearPasskeyEnrollments(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("vault: clear passkeys (begin): %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`DELETE FROM passkey_unlock`,
		`DELETE FROM passkey`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("vault: clear passkeys: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vault: clear passkeys (commit): %w", err)
	}
	return nil
}

// scanPasskey reads one row into a Passkey. Works for both *sql.Row and
// *sql.Rows (both satisfy the Scan signature).
func scanPasskey(sc interface{ Scan(...any) error }) (Passkey, error) {
	var pk Passkey
	var signCount, be, bs, createdSec int64
	if err := sc.Scan(&pk.CredentialID, &pk.PublicKey, &signCount, &pk.AAGUID,
		&pk.Transports, &pk.Label, &be, &bs, &createdSec); err != nil {
		return Passkey{}, err
	}
	pk.SignCount = uint32(signCount) // #nosec G115 -- written as int64(uint32); always in range
	pk.BackupEligible = be != 0
	pk.BackupState = bs != 0
	pk.CreatedAt = time.Unix(createdSec, 0).UTC()
	return pk, nil
}
