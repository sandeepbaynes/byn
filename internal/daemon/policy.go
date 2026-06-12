package daemon

// policy.go — per-scope [auth] policy lookup from the trust store.
//
// policyFor resolves the effective [auth] policy map for a given vault + scope
// by examining every trusted record whose VKMAC verifies under the vault's
// current key. It is called by authorizeAction (the per-action gate) to allow
// trusted .byn files to override the session gate:
//
//   - policy[action] == "always" → call authorizeActionAlways unconditionally
//     (tightens: forces fresh auth even with an active session).
//   - policy[action] == "none"   → skip the gate (relaxes: free even when no
//     session is present, but ONLY for the matched scope).
//   - absent or ok==false        → the session gate decides (existing behavior).
//
// Design notes:
//
//   - No caching: the trust store is small and disk I/O is cheap; caching
//     would trade a rare consistency hazard (a fresh grant not taking effect
//     until the daemon restarts) for a negligible speed gain.
//
//   - Locked vault ⇒ ok=false: the VKMAC key requires the unlocked vault key.
//     Policy is only as trustworthy as the MAC that binds it; without the MAC
//     key we cannot verify the record was not tampered with, so we fall back to
//     flag semantics. This is intentional and documented to callers.
//
//   - Only v2 records with non-empty Auth are considered. v1 records carry no
//     Auth and are never policy sources.

import (
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// policyFor returns the effective [auth] policy for the given (vaultName,
// scope) pair, or ok=false when:
//   - the vault is locked (MAC key unavailable — see design note above),
//   - trusted_byn.json is absent (fresh install), or
//   - no record matches the scope with a valid VKMAC.
//
// When multiple records match at the same specificity level, the strictest
// value wins per key ("always" > absent > "none"). When records match at
// different specificity levels, the most specific record wins per key.
//
// Specificity, from most to least specific:
//
//	vault + project + env  (all three present and matching)
//	vault + project        (env unset on the record)
//	vault-only             (project and env unset on the record)
//
// "unset" means the record field is "" — which normalizes to the default
// name ("default") before comparison, matching the same defaultIfEmpty
// rule used throughout the daemon.
func (d *Daemon) policyFor(vaultName string, scope vault.Scope) (policy map[string]string, ok bool) {
	// Derive the VKMAC key. Requires the vault to be unlocked.
	e := d.lookupVault(vaultName)
	if e == nil || e.store.IsLocked() {
		// Locked vault: VKMAC key unavailable. Documented fall-through.
		return nil, false
	}
	vkKey, err := e.store.DeriveSubkey(trust.VKMACKeyInfo)
	if err != nil {
		return nil, false
	}
	defer zeroBytes(vkKey)

	store, err := trust.Load(d.cfg.Dir)
	if err != nil || len(store.Records) == 0 {
		return nil, false
	}

	// Normalize request scope: "" → "default".
	reqProject := defaultIfEmpty(scope.Project, vault.DefaultProjectName)
	reqEnv := defaultIfEmpty(scope.Env, vault.DefaultEnvName)

	// We accumulate per-key winners across all matching records, tracking the
	// specificity at which each key was last set. Higher specificity always wins;
	// at the same specificity level the strictest value wins.
	type winner struct {
		value       string
		specificity int // 1=vault-only, 2=vault+project, 3=vault+project+env
	}
	winners := make(map[string]winner)

	for _, rec := range store.Records {
		// Only v2 records with non-empty Auth and a valid VKMAC.
		if !rec.IsV2() || len(rec.Auth) == 0 {
			continue
		}
		if !rec.VerifyVKMAC(vkKey) {
			continue
		}

		// The record's vault must match (empty record vault = "default").
		recVault := defaultIfEmpty(rec.Vault, vault.DefaultVaultName)
		if recVault != vaultName {
			continue
		}

		// Compute specificity and check scope match.
		recProject := defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName)
		recEnv := defaultIfEmpty(rec.ScopeEnv, vault.DefaultEnvName)

		var spec int
		switch {
		case rec.ScopeProject == "" && rec.ScopeEnv == "":
			// vault-only record: matches any project/env within this vault.
			spec = 1
		case rec.ScopeEnv == "":
			// vault+project record: matches only when project matches.
			if recProject != reqProject {
				continue
			}
			spec = 2
		default:
			// vault+project+env record: must match both.
			if recProject != reqProject || recEnv != reqEnv {
				continue
			}
			spec = 3
		}

		// Merge this record's Auth entries into winners using specificity +
		// strictest-tie rules.
		for k, v := range rec.Auth {
			w, exists := winners[k]
			if !exists || spec > w.specificity {
				// First match or more specific: take this value directly.
				winners[k] = winner{value: v, specificity: spec}
			} else if spec == w.specificity {
				// Same specificity: strictest wins ("always" > absent > "none").
				winners[k] = winner{value: strictest(w.value, v), specificity: spec}
			}
			// Lower specificity: ignore.
		}
	}

	if len(winners) == 0 {
		return nil, false
	}

	out := make(map[string]string, len(winners))
	for k, w := range winners {
		out[k] = w.value
	}
	return out, true
}

// strictest returns the stricter of two [auth] policy values.
// Order (strongest to weakest): "always" > "none".
// Any other value (including "") is treated as neutral / absent.
// When one value is "always", always wins. When one is "none" and the other is
// not "always", "none" loses to the other (i.e., "always" beats "none").
// Between two equal values or two neutral values the first (a) is returned.
func strictest(a, b string) string {
	if a == "always" || b == "always" {
		return "always"
	}
	// "none" is weaker than any non-"always" value; prefer the other.
	if a == "none" {
		return b
	}
	return a
}
