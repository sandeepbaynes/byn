package vault

import (
	"context"
	"errors"
	"fmt"

	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// Rows a non-default env inherits.
//
// A read in prod falls back to default when prod has no row of its own, and
// that row is sealed under DEFAULT's keys: its scope key if an owner wrote it,
// its authored key if an agent wrote it while the vault was locked. A
// capability issued for prod used to carry only prod's keys, so exec could see
// such a value (the listing inherits it, `byn get` opens it with the vault key)
// and then deliver nothing — silently, and only for the values that happened
// to live in default. The keys below are what a grant for a non-default env
// carries so exec follows the same inheritance rule every read does.

// CapDefaultScopeKeyName is the reserved capability entry holding the default
// env's scope key, carried by a WILDCARD grant for a non-default env. The NUL
// byte, which validateEntryName rejects, keeps it out of the entry-name space.
const CapDefaultScopeKeyName = "\x00scope@default"

// CapDefaultAuthoredKeyName is the reserved capability entry holding the
// default env's authored key, carried by every grant for a non-default env.
// NUL-prefixed for the same reason.
const CapDefaultAuthoredKeyName = "\x00authored@default"

// CaptureDefaultKeys returns the keys a grant in scope needs for the rows it
// inherits from the project's default env: default's authored key always, and
// default's scope key when wildcard. Both are nil when scope already IS the
// default env, or when the project has no default env yet.
//
// vaultKey is used when non-nil; otherwise the in-memory key, which returns
// ErrLocked while locked. The caller owns and must zero both results.
//
// An explicit-name grant does not get the scope key: its per-row keys already
// follow inheritance (captureRowKeys resolves through fetchEnvVarInherited), so
// the only inherited rows it cannot open are the authored ones.
func (s *Store) CaptureDefaultKeys(ctx context.Context, scope Scope, wildcard bool, vaultKey []byte) (kenv, kauth []byte, err error) {
	if scope.Env == "" || scope.Env == DefaultEnvName {
		return nil, nil, nil
	}
	vk := vaultKey
	if vk == nil {
		vk = s.snapshotVaultKey()
		if vk == nil {
			return nil, nil, ErrLocked
		}
		defer zero(vk)
	}
	projectID, _, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defaultEnvID, err := s.envIDByName(ctx, projectID, DefaultEnvName)
	if err != nil {
		if errors.Is(err, ErrEnvNotFound) {
			return nil, nil, nil // nothing to inherit
		}
		return nil, nil, err
	}
	kauth, err = s.AuthoredKey(vk, projectID, defaultEnvID)
	if err != nil {
		return nil, nil, err
	}
	if wildcard {
		kenv, err = s.EnvKey(vk, projectID, defaultEnvID)
		if err != nil {
			zero(kauth)
			return nil, nil, err
		}
	}
	return kenv, kauth, nil
}

// InheritedKeys are the default-env keys a capability may carry; either may be
// nil. Passed to the Open* calls below so an inherited row opens without the
// vault key.
type InheritedKeys struct {
	Scope    []byte // default env's K_env (wildcard grants only)
	Authored []byte // default env's K_auth
}

// OpenEnvVarInherited opens a row name resolves to in scope — its own or the
// one it inherits from default — using ONLY capability keys: own is the
// scope's K_env (may be nil), ownAuth its K_auth (may be nil), dflt the default
// env's pair.
//
// It covers exactly the v3 (scope-key) and v4 (authored) schemes; the flat
// per-row schemes are opened with per-row keys elsewhere. A row none of the
// supplied keys can open reports ErrInheritedUnreachable, which exec turns into
// a named, actionable line rather than a silently missing variable.
func (s *Store) OpenEnvVarInherited(ctx context.Context, scope Scope, name string, own, ownAuth []byte, dflt InheritedKeys) ([]byte, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	r, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	inherited := rowEnvID != envID
	var key []byte
	switch r.AADVersion {
	case aadVersionEnvKey:
		key = own
		if inherited {
			key = dflt.Scope
		}
		if len(key) == 0 {
			return nil, unreachable(name, inherited, false)
		}
		krow, kerr := vcrypto.DeriveRowKeyFromEnvKey(key, rowAAD(kindAADEnvVar, name))
		if kerr != nil {
			return nil, kerr
		}
		defer zero(krow)
		return vcrypto.DecryptWithAAD(krow, r.Value, s.entryAADV3(projectID, rowEnvID, kindAADEnvVar, name))
	case aadVersionAuthoredKey:
		key = ownAuth
		if inherited {
			key = dflt.Authored
		}
		if len(key) == 0 {
			return nil, unreachable(name, inherited, true)
		}
		krow, kerr := authoredRowKey(key, kindAADEnvVar, name)
		if kerr != nil {
			return nil, kerr
		}
		defer zero(krow)
		return vcrypto.DecryptWithAAD(krow, r.Value, s.entryAADV3(projectID, rowEnvID, kindAADEnvVar, name))
	default:
		return nil, errScopeKeyUnsupported
	}
}

// ErrInheritedUnreachable marks a value that exists but that the capability
// holds no key for. Wrapped with the detail exec needs to say why.
var ErrInheritedUnreachable = errors.New("vault: value exists but this grant holds no key for it")

// UnreachableDetail is carried by an ErrInheritedUnreachable error.
type UnreachableDetail struct {
	Name       string
	Inherited  bool // the row lives in the default env
	Unattended bool // the row was stored unattended (authored scheme)
}

func (u *UnreachableDetail) Error() string {
	return fmt.Sprintf("%v: %q (inherited=%t, unattended=%t)", ErrInheritedUnreachable, u.Name, u.Inherited, u.Unattended)
}

func (u *UnreachableDetail) Unwrap() error { return ErrInheritedUnreachable }

func unreachable(name string, inherited, unattended bool) error {
	return &UnreachableDetail{Name: name, Inherited: inherited, Unattended: unattended}
}

// SealUnattended re-seals name in scope's OWN row from the authored scheme to
// the current one, so the value is protected by the vault key — the master
// password — instead of only by this machine. The plaintext never leaves the
// store and is zeroed before return.
//
// Returns sealed=false with no error when the row is not on the authored
// scheme (already protected, nothing to do). ErrNotFound when scope has no row
// of its own: inherited rows are sealed in the env that owns them.
func (s *Store) SealUnattended(ctx context.Context, scope Scope, name string) (sealed bool, err error) {
	vk := s.snapshotVaultKey()
	if vk == nil {
		return false, ErrLocked
	}
	defer zero(vk)
	return s.SealUnattendedWithKey(ctx, vk, scope, name)
}

// SealUnattendedWithKey is SealUnattended for a caller holding the vault key.
func (s *Store) SealUnattendedWithKey(ctx context.Context, vaultKey []byte, scope Scope, name string) (bool, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return false, err
	}
	r, found, err := s.fetchEntry(ctx, projectID, envID, kindAADEnvVar, name)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrNotFound
	}
	if r.AADVersion != aadVersionAuthoredKey {
		return false, nil
	}
	pt, err := s.openEntry(vaultKey, r.AADVersion, projectID, envID, kindAADEnvVar, name, r.Value)
	if err != nil {
		return false, err
	}
	defer zero(pt)
	ct, err := s.sealEntry(vaultKey, projectID, envID, kindAADEnvVar, name, pt)
	if err != nil {
		return false, err
	}
	// Guarded on the version read above: a concurrent write that already
	// replaced the row must not be overwritten with the older value.
	res, err := s.db.ExecContext(ctx,
		`UPDATE entries SET value=?, aad_version=? WHERE project_id=? AND env_id=? AND kind='env_var' AND name=? AND aad_version=?`,
		ct, currentAADVersion, projectID, envID, name, aadVersionAuthoredKey)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// UnattendedEntry names one value stored on the authored scheme.
type UnattendedEntry struct {
	Project string
	Env     string
	Name    string
}

// ListUnattended returns every value in the vault still sealed under an
// authored key — the ones protected by this machine rather than the master
// password. Names only; works while locked.
func (s *Store) ListUnattended(ctx context.Context) ([]UnattendedEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.name, e.name, n.name
		   FROM entries n
		   JOIN projects p ON p.id = n.project_id
		   JOIN envs e ON e.id = n.env_id
		  WHERE n.kind = 'env_var' AND n.aad_version = ?
		  ORDER BY p.name, e.name, n.name`, aadVersionAuthoredKey)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UnattendedEntry
	for rows.Next() {
		var u UnattendedEntry
		if err := rows.Scan(&u.Project, &u.Env, &u.Name); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// EntryOrigin reports where name resolves in scope: whether the row is
// inherited from the default env, and whether it is still sealed under an
// authored key (stored unattended). found is false when neither env has it.
// Reads metadata only, so it works while locked.
func (s *Store) EntryOrigin(ctx context.Context, scope Scope, name string) (inherited, unattended, found bool, err error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return false, false, false, err
	}
	r, rowEnvID, found, err := s.fetchEnvVarInherited(ctx, projectID, envID, scope.Env, name)
	if err != nil || !found {
		return false, false, false, err
	}
	return rowEnvID != envID, r.AADVersion == aadVersionAuthoredKey, true, nil
}

// CaptureScopeKeyWithKey is CaptureScopeKey for a caller already holding the
// vault key (a locked vault, key unwrapped once for a batch of work).
func (s *Store) CaptureScopeKeyWithKey(ctx context.Context, vaultKey []byte, scope Scope) ([]byte, error) {
	projectID, envID, err := s.scopeIDs(ctx, scope)
	if err != nil {
		return nil, err
	}
	return s.EnvKey(vaultKey, projectID, envID)
}

// CaptureAuthoredKeyWithKey is CaptureAuthoredKey for a caller already holding
// the vault key.
func (s *Store) CaptureAuthoredKeyWithKey(ctx context.Context, vaultKey []byte, scope Scope) ([]byte, error) {
	return s.authoredKeyForScope(ctx, vaultKey, scope)
}

// DeriveSubkeyWithKey is DeriveSubkey for a caller already holding the vault key.
func DeriveSubkeyWithKey(vaultKey []byte, info string) ([]byte, error) {
	return hkdfSubkey(vaultKey, info)
}
