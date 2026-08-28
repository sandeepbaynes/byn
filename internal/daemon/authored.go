package daemon

import (
	"context"
	"path"
	"path/filepath"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
	vcrypto "github.com/sandeepbaynes/byn/internal/vault/crypto"
)

// Self-authored variables — the decisions. The registry that remembers who
// created what is in authoredstore.go; the key that lets a locked vault store a
// value at all is in internal/vault/authored.go.
//
// The rule byn enforces, in one sentence: a caller may freely create, update
// and read the values it authored, and nothing else. Everything below is that
// sentence applied to one code path or another.

// authoredScopeKey builds the registry key for a variable.
func authoredScopeKey(vaultName string, scope vault.Scope, name string) authoredKey {
	return authoredKey{
		Vault:   defaultIfEmpty(vaultName, vault.DefaultVaultName),
		Project: defaultIfEmpty(scope.Project, vault.DefaultProjectName),
		Env:     defaultIfEmpty(scope.Env, vault.DefaultEnvName),
		Name:    name,
	}
}

// recordAuthored notes that the caller created name in scope.
//
// Called only on a genuine CREATE. An overwrite is a different act — it is
// authorization-gated precisely because the person doing it may not be the one
// who owns the value — so it earns no authorship.
//
// Best-effort: a failure records nothing, which costs the caller an approval
// later rather than granting one by accident.
func (d *Daemon) recordAuthored(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope, name string, authored, unattended bool) {
	if d.authored == nil {
		return
	}
	origin := callerOriginFn(callerFrom(ctx).PID)
	if !origin.ok() {
		return // no pinned-down caller identity → nothing worth recording
	}
	if err := d.authored.Record(authoredScopeKey(vaultName, scope, name), origin, authored, unattended); err != nil {
		return
	}
	// An entry on the authored scheme is keyed through the scope's authored key,
	// which every capability already carries — so exec can open it without any
	// per-name key. An ordinary row needs its key added to the capability, or a
	// locked daemon will allow the name and then decrypt nothing.
	if !authored {
		d.refreshCapabilitiesFor(ctx, st, vaultName, scope)
	}
	d.auditEmit(ctx, vaultName, audit.Event{
		Project: scope.Project, Env: scope.Env, Kind: "env_var", EntryName: name,
		Op: "trust_self_authored", Outcome: audit.OutcomeOK,
	})
}

// forgetAuthored revokes authorship of names in scope, and is what stops an
// agent from creating a placeholder, having a person replace it with the real
// credential, and reading that credential back as its own.
func (d *Daemon) forgetAuthored(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope, names ...string) {
	if d.authored == nil {
		return
	}
	key := authoredScopeKey(vaultName, scope, "")
	if err := d.authored.Forget(key.Vault, key.Project, key.Env, names...); err != nil {
		return
	}
	d.refreshCapabilitiesFor(ctx, st, vaultName, scope)
}

// ownUnattendedValue reports whether this caller may treat name as its own: byn
// recorded it as the author, this command is running under that same origin,
// and the value is one byn took in unattended.
//
// The origin keeps the exemption from spreading — another terminal, another
// editor window, or a background service did not create the value and does not
// inherit the right to read or replace it. The unattended condition keeps it
// from reaching backwards: something stored by an authenticated caller was
// protected by that credential from the start and still needs it.
func (d *Daemon) ownUnattendedValue(ctx context.Context, vaultName string, scope vault.Scope, name string) bool {
	e, ok := d.authoredEntryFor(ctx, vaultName, scope, name)
	return ok && e.Authored
}

// authoredEntryFor returns the authorship of name when this caller shares the
// origin that created it.
func (d *Daemon) authoredEntryFor(ctx context.Context, vaultName string, scope vault.Scope, name string) (authoredEntry, bool) {
	if d.authored == nil {
		return authoredEntry{}, false
	}
	e, ok := d.authored.Lookup(authoredScopeKey(vaultName, scope, name))
	if !ok {
		return authoredEntry{}, false
	}
	if !sharesOriginFn(callerFrom(ctx).PID, procRef{PID: e.OriginPID, Start: e.OriginStart}) {
		return authoredEntry{}, false
	}
	return e, true
}

// refreshCapabilitiesFor re-seals the exec capability of every trusted .byn
// governing a scope, so it carries a key for each name the project may inject.
func (d *Daemon) refreshCapabilitiesFor(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope) {
	if st == nil || st.IsLocked() {
		return // re-sealing captures row keys, which needs the vault key
	}
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || store == nil {
		return
	}
	vkKey, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		return
	}
	defer zeroBytes(vkKey)

	key := authoredScopeKey(vaultName, scope, "")
	authoredNames := d.authored.NamesFor(key.Vault, key.Project, key.Env)

	for _, rec := range store.Records {
		if !recordGoverns(rec, vaultName, scope) || len(rec.ExecCapability) == 0 {
			continue
		}
		parsed, perr := bynfile.Parse([]byte(rec.Snapshot))
		if perr != nil || parsed.AllowsAll() {
			continue // a wildcard grant already derives its own row keys
		}
		names := append([]string(nil), []string(parsed.Exec.Env)...)
		names = append(names, authoredNames...)
		blob, cerr := d.sealExecCapability(ctx, st, scope, names, false, nil)
		if cerr != nil || len(blob) == 0 {
			continue
		}
		rec.ExecCapability = blob
		rec.SetMACs(d.fpMACKey, vkKey)
		_, _ = trust.Put(d.cfg.Dir, rec)
	}
}

// recordGoverns reports whether rec's grant covers the given vault and scope.
func recordGoverns(rec trust.Record, vaultName string, scope vault.Scope) bool {
	if defaultIfEmpty(rec.Vault, vault.DefaultVaultName) != defaultIfEmpty(vaultName, vault.DefaultVaultName) {
		return false
	}
	if defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName) != defaultIfEmpty(scope.Project, vault.DefaultProjectName) {
		return false
	}
	return defaultIfEmpty(rec.ScopeEnv, vault.DefaultEnvName) == defaultIfEmpty(scope.Env, vault.DefaultEnvName)
}

// forgivesSelfAuthored reports whether every widening in delta is a variable
// this caller authored, and so needs no human.
//
// All of these must hold for each added name:
//
//  1. byn recorded this caller's origin as its author (authoredByCaller).
//  2. The vault says it was created AFTER this project was trusted. A secret
//     that predates the grant is a pre-existing one, and exposing it to the
//     project's commands for the first time is a real widening.
//  3. It has not been written again since. An overwrite is authorization-gated,
//     so the stored value may have come from someone other than the author.
//
// Anything else in the delta — a new command, a scope move, an auth relaxation
// — disqualifies the whole change: a mixed request is decided as one thing.
func (d *Daemon) forgivesSelfAuthored(ctx context.Context, st *vault.Store, rec trust.Record, delta trust.Delta, vaultName string, scope vault.Scope) bool {
	if delta.ScopeChanged || len(delta.Widenings) == 0 {
		return false
	}
	for _, w := range delta.Widenings {
		if w.Kind != "env" || w.Name == "" {
			return false // includes the "*" widening, which carries no name
		}
	}
	infos, err := st.ListEnvVars(ctx, scope)
	if err != nil {
		return false
	}
	present := make(map[string]vault.EntryInfo, len(infos))
	for _, m := range infos {
		present[m.Name] = m
	}
	for _, w := range delta.Widenings {
		e, ok := d.authoredEntryFor(ctx, vaultName, scope, w.Name)
		if !ok || !e.Authored {
			// Same line as the read and replace exemptions: only values byn
			// took in unattended. A secret stored by someone who was
			// authenticated at the time was protected by that credential from
			// the start, and adding it to a project's allowlist is a decision a
			// person should still see.
			return false
		}
		info, ok := present[w.Name]
		if !ok || info.Source != vault.SourceScope {
			return false // absent, or inherited from the default env
		}
		// Both readings come from the daemon's clock. Comparing authorship
		// against the .byn's mtime instead looks equivalent and is not: a
		// filesystem records mtime about a millisecond coarse, so a file written
		// after a secret was created can carry a timestamp before it, and a
		// pre-existing secret is then forgiven. That was reproducible.
		//
		// Authorship is recorded for every create, including ones made before
		// this .byn was ever trusted, so this comparison is load-bearing: it is
		// the only thing keeping a pre-existing secret out.
		grantedAt := rec.GrantedAtUnixNano
		if grantedAt == 0 {
			grantedAt = rec.MTimeUnixNano // granted before byn recorded the moment
		}
		if e.AtUnixNano <= grantedAt {
			return false
		}
		// Belt and braces behind forgetAuthored, which revokes authorship at the
		// moment of an overwrite. This catches one that landed in a later second
		// without going through that path.
		if info.UpdatedAt.After(info.CreatedAt) {
			return false
		}
	}
	return true
}

// authoredKeyFor unseals the scope's self-authored key from any trusted .byn
// that governs it, so the daemon can write and read the caller's own values
// while the vault is locked.
//
// Returns nil when no trusted .byn covers this scope, which is the honest
// answer rather than a failure: byn holds no key for a scope nobody has granted
// it authority over, so there is nothing it could encrypt with. The caller is
// told exactly that instead of being asked for a password that would not help.
func (d *Daemon) authoredKeyFor(vaultName string, scope vault.Scope) []byte {
	if d.fpMACKey == nil {
		return nil
	}
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || store == nil {
		return nil
	}
	capKey, err := vcrypto.DeriveCapKey(d.fpMACKey)
	if err != nil {
		return nil
	}
	defer zeroBytes(capKey)
	for _, rec := range store.Records {
		if !recordGoverns(rec, vaultName, scope) || len(rec.ExecCapability) == 0 {
			continue
		}
		keys, oerr := vcrypto.OpenCapability(capKey, rec.ExecCapability)
		if oerr != nil {
			continue
		}
		authKey := keys[vault.CapAuthoredKeyName]
		for name, k := range keys {
			if name != vault.CapAuthoredKeyName {
				zeroBytes(k)
			}
		}
		if len(authKey) > 0 {
			return authKey
		}
	}
	return nil
}

// scopeLabel renders a scope the way a person writes it, for error messages.
func scopeLabel(scope vault.Scope) string {
	return defaultIfEmpty(scope.Project, vault.DefaultProjectName) + "/" +
		defaultIfEmpty(scope.Env, vault.DefaultEnvName)
}

// policyDemandsAuth reports whether the governing .byn insists on a credential
// for this action, whatever else byn might conclude.
//
// A locked vault cannot read the policy (its MAC key needs the vault key), and
// that answers false — the same fall-through the rest of the policy layer takes,
// and the same reason: a policy byn cannot verify is not one it can enforce.
func (d *Daemon) policyDemandsAuth(vaultName string, scope vault.Scope, action string) bool {
	policy, ok := d.policyFor(vaultName, scope)
	if !ok {
		return false
	}
	return policy[action] == "always"
}

// readAuthored decrypts one entry through the scope's authored key, which is
// the only key a LOCKED vault has. Reports whether it could.
//
// It succeeds only for a value the caller authored and that was written while
// locked; anything else was sealed under the vault key and stays that way.
func (d *Daemon) readAuthored(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope, name string, mine bool) (vault.Entry, bool) {
	if !mine || !st.IsLocked() {
		return vault.Entry{}, false
	}
	authKey := d.authoredKeyFor(vaultName, scope)
	if authKey == nil {
		return vault.Entry{}, false
	}
	defer zeroBytes(authKey)
	value, err := st.OpenEnvVarAuthored(ctx, scope, name, authKey)
	if err != nil {
		return vault.Entry{}, false
	}
	return vault.Entry{Name: name, Value: value}, true
}

// callerIsAttended reports whether a human stands behind this request — a VALID
// session for this vault and caller, or credentials supplied with the call.
//
// Validity is the point, and it is where the first version of this was wrong.
// Testing merely that a session token was PRESENT looked equivalent and was
// not: the CLI keeps a token on disk and sends it on every call, so one left
// behind by an earlier unlock — after a daemon restart, after the session
// expired, after `byn lock` — made every subsequent agent look attended. The
// effect was that nothing an agent stored got the unattended treatment, and
// `byn put` went back to demanding a password on a locked vault. That is
// exactly the symptom this was built to remove, and only a live run found it:
// tests construct their clients fresh and never carry a stale token.
func (d *Daemon) callerIsAttended(ctx context.Context, vaultName string, password, presenceToken []byte) bool {
	if len(password) > 0 || len(presenceToken) > 0 {
		return true
	}
	tok := string(callerSession(ctx))
	if tok == "" {
		return false
	}
	ci := callerFrom(ctx)
	return d.sessions.validate(tok, vaultName, ci.UID, ci.TTYDev, time.Now())
}

// unattendedPutAllowed reports whether a caller with no credential may create
// name in this scope.
//
// The .byn that governs the scope decides. Absent means yes: an agent that
// cannot store what it invents is the problem byn exists to remove, so the
// default is permissive and loud rather than restrictive and quiet. A project
// that provisions its secrets by hand can set [exec] agent_put = false, or name
// individual variables in [exec] agent_put_deny.
//
// Read from the record's MAC-bound snapshot rather than the file on disk, for
// the same reason every other policy is: editing the .byn after trust must not
// change what byn enforces.
func (d *Daemon) unattendedPutAllowed(vaultName string, scope vault.Scope, name string) (bool, string) {
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || store == nil {
		return true, ""
	}
	for _, rec := range store.Records {
		if !recordGoverns(rec, vaultName, scope) || rec.Snapshot == "" {
			continue
		}
		parsed, perr := bynfile.Parse([]byte(rec.Snapshot))
		if perr != nil {
			continue
		}
		if parsed.Exec.AgentPut != nil && !*parsed.Exec.AgentPut {
			return false, filepath.Base(rec.Path) + " sets [exec] agent_put = false"
		}
		if pattern, denied := matchesDenyPattern(parsed.Exec.AgentPutDeny, name); denied {
			return false, filepath.Base(rec.Path) + " denies " + pattern + " in [exec] agent_put_deny"
		}
	}
	return true, ""
}

// matchesDenyPattern reports whether name is covered by any deny entry, and by
// which one. Entries are shell-style globs; a literal name is simply a glob
// with no metacharacters, so both forms work through one path.
//
// A malformed pattern matches nothing rather than everything: a typo in a deny
// list must not silently refuse every write, which would look like byn being
// broken rather than like a bad pattern.
func matchesDenyPattern(patterns []string, name string) (string, bool) {
	for _, p := range patterns {
		if p == name {
			return p, true
		}
		if ok, err := path.Match(p, name); err == nil && ok {
			return p, true
		}
	}
	return "", false
}
