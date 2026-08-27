package daemon

import (
	"context"
	"time"

	"github.com/sandeepbaynes/byn/internal/audit"
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Self-authored variables — the daemon half. See internal/trust/authored.go for
// why this exists; this file is the part that decides.

// recordSelfAuthored notes that the caller just created name in scope, on every
// trusted .byn that governs that scope.
//
// Called only on a genuine CREATE. An overwrite is a different act: it is
// authorization-gated precisely because the person doing it may not be the
// person who owns the value, so it earns no authorship.
//
// Entirely best-effort. Every failure path leaves the record untouched, which
// costs the caller one approval later rather than granting anything by
// accident — the safe direction for a bookkeeping step that runs on a hot path.
func (d *Daemon) recordSelfAuthored(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope, name string) {
	origin := callerOriginFn(callerFrom(ctx).PID)
	if !origin.ok() {
		return // no pinned-down caller identity → nothing worth recording
	}
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || store == nil {
		return
	}
	// Re-MAC needs both keys. The vault is unlocked here (the value was just
	// encrypted), so the vault-key layer is available; without it the record
	// would be left with a stale VKMAC and fail at use time, so a failure to
	// derive means write nothing at all.
	vkKey, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		return
	}
	defer zeroBytes(vkKey)

	for _, rec := range store.Records {
		if !recordGoverns(rec, vaultName, scope) {
			continue
		}
		// Always replace any existing entry. This runs only on a CREATE, so the
		// name did not exist a moment ago; whatever authorship was recorded for
		// an earlier incarnation of it belongs to a value that is gone, and
		// letting it stand would hand its author a grant over someone else's.
		rec.SelfAuthored = trust.WithAuthored(rec.SelfAuthored, trust.AuthoredGrant{
			Name:        name,
			OriginPID:   origin.PID,
			OriginStart: origin.Start,
			AtUnixNano:  time.Now().UnixNano(),
		})
		// The sealed capability is what a LOCKED daemon injects from, and it
		// holds one key per name captured at grant. A name created afterwards
		// has no key in it, so recording the authorship without refreshing the
		// capability would produce a grant that silently injects nothing.
		// Wildcard grants already carry the scope key and derive their own.
		if !d.refreshCapabilityFor(ctx, st, &rec, scope) {
			continue
		}
		rec.SetMACs(d.fpMACKey, vkKey)
		if _, perr := trust.Put(d.cfg.Dir, rec); perr != nil {
			continue
		}
		d.auditEmit(ctx, vaultName, audit.Event{
			Project:   scope.Project,
			Env:       scope.Env,
			Kind:      "env_var",
			EntryName: name,
			BynPath:   rec.Path,
			Op:        "trust_self_authored",
			Outcome:   audit.OutcomeOK,
		})
	}
}

// forgetSelfAuthored revokes any authorship of name in scope.
//
// Called when the stored value stops being the author's: an overwrite (which is
// authorization-gated precisely because someone else may be doing it), a
// delete, or a rename away from the name. Without this, an agent could create a
// placeholder, have a person replace it with the real credential, and then read
// that credential back as if it were still its own.
//
// Best-effort in the same way as recording, but it fails the other way: if the
// record cannot be rewritten the authorship stays, so this must not be the only
// thing standing between a caller and a value it did not author — the checks in
// forgivesSelfAuthored are.
func (d *Daemon) forgetSelfAuthored(ctx context.Context, st *vault.Store, vaultName string, scope vault.Scope, names ...string) {
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || store == nil {
		return
	}
	vkKey, derr := st.DeriveSubkey(trust.VKMACKeyInfo)
	if derr != nil {
		return
	}
	defer zeroBytes(vkKey)

	for _, rec := range store.Records {
		if !recordGoverns(rec, vaultName, scope) {
			continue
		}
		kept := rec.SelfAuthored[:0:0]
		for _, a := range rec.SelfAuthored {
			drop := false
			for _, n := range names {
				if a.Name == n {
					drop = true
					break
				}
			}
			if !drop {
				kept = append(kept, a)
			}
		}
		if len(kept) == len(rec.SelfAuthored) {
			continue
		}
		revoked := rec.SelfAuthored
		rec.SelfAuthored = kept
		rec.SetMACs(d.fpMACKey, vkKey)
		if _, perr := trust.Put(d.cfg.Dir, rec); perr != nil {
			continue
		}
		// Worth a line in the log: it is the moment a caller stopped being able
		// to add a variable to this project without asking.
		for _, a := range revoked {
			if _, still := rec.AuthoredBy(a.Name); still {
				continue
			}
			d.auditEmit(ctx, vaultName, audit.Event{
				Project:   scope.Project,
				Env:       scope.Env,
				Kind:      "env_var",
				EntryName: a.Name,
				BynPath:   rec.Path,
				Op:        "trust_self_authored_revoked",
				Outcome:   audit.OutcomeOK,
			})
		}
	}
}

// refreshCapabilityFor re-seals rec's exec capability so it carries a row key
// for every name the record may inject, including the ones just authored.
// Reports whether the record is fit to write.
//
// A record with no capability keeps none: it is a .byn with no [exec] env
// allowlist, or a machine with no fingerprint, and exec falls back to a
// password there anyway.
func (d *Daemon) refreshCapabilityFor(ctx context.Context, st *vault.Store, rec *trust.Record, scope vault.Scope) bool {
	if len(rec.ExecCapability) == 0 {
		return true
	}
	parsed, perr := bynfile.Parse([]byte(rec.Snapshot))
	if perr != nil {
		return false
	}
	if parsed.AllowsAll() {
		return true // wildcard: the sealed scope key already derives new rows
	}
	// Everything the record may inject: the granted allowlist plus the names
	// authored since (including the one being added right now).
	names := append([]string(nil), []string(parsed.Exec.Env)...)
	for _, a := range rec.SelfAuthored {
		names = append(names, a.Name)
	}
	blob, cerr := d.sealExecCapability(ctx, st, scope, names, false, nil)
	if cerr != nil || len(blob) == 0 {
		return false
	}
	rec.ExecCapability = blob
	return true
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
// All three conditions must hold for each added name:
//
//  1. byn recorded the caller's origin as its author, and this command is
//     running under that same origin — a different terminal, editor window, or
//     service does not inherit the exemption.
//  2. The vault says it was created AFTER this project was trusted. A secret
//     that predates the grant is a pre-existing one; exposing it to the
//     project's commands for the first time is a real widening.
//  3. It has never been written again since. An overwrite is authorization-
//     gated, so the value now stored may have come from someone other than the
//     author — the author's claim to already know it does not survive.
//
// Anything else in the delta (a new command, a scope move, an auth relaxation)
// disqualifies the whole change: those are not covered by authorship, and a
// mixed request is decided as one thing.
func (d *Daemon) forgivesSelfAuthored(ctx context.Context, st *vault.Store, rec trust.Record, delta trust.Delta, scope vault.Scope) bool {
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
	created := make(map[string]vault.EntryInfo, len(infos))
	for _, m := range infos {
		created[m.Name] = m
	}
	for _, w := range delta.Widenings {
		g, ok := rec.AuthoredBy(w.Name)
		if !ok || !sharesOriginFn(callerFrom(ctx).PID, procRef{PID: g.OriginPID, Start: g.OriginStart}) {
			return false
		}
		info, ok := created[w.Name]
		if !ok || info.Source != vault.SourceScope {
			return false // absent, or inherited from the default env
		}
		// entries.created_at is stored in whole seconds, so this compares
		// seconds; a nanosecond comparison against the grant silently never
		// matched. Same-second equality is allowed because an authorship entry
		// cannot predate the record that holds it — byn only writes one onto a
		// .byn it has already granted — so this is a sanity check against the
		// vault itself rather than the load-bearing test.
		if info.CreatedAt.Unix() < rec.MTimeUnixNano/int64(time.Second) {
			return false // predates the grant
		}
		// Belt and braces behind forgetSelfAuthored, which revokes authorship at
		// the moment of an overwrite. This catches one that landed in a later
		// second without going through that path.
		if info.UpdatedAt.After(info.CreatedAt) {
			return false // overwritten since it was authored
		}
	}
	return true
}
