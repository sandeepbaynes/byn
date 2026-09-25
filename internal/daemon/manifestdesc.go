package daemon

import (
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/trust"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Descriptions a .byn declares.
//
// They are read from the trust record's SNAPSHOT, never from the file on disk.
// That is what makes this the strong layer: the snapshot is covered by the
// record MAC and the record lives in the daemon's own directory, so an agent
// that edits ./.byn to plant instructions changes nothing until the owner
// re-approves the file and sees the change in `byn trust diff`. A description
// stored against a variable in the vault has no such ceremony behind it —
// an unattended caller may write one at creation — so the two layers are shown
// separately rather than merged.
//
// Verification degrades with the vault's state, honestly: with the vault
// unlocked the vault-key MAC is checked, which a same-UID forger cannot
// produce; locked, only the machine-fingerprint MAC can be checked, which is a
// weaker claim. The text is advisory either way, and the substantive control is
// that the snapshot is what is read at all.

// manifestDescription returns the description a trusted .byn declares for one
// variable in scope.
func (d *Daemon) manifestDescription(vaultName string, scope vault.Scope, name string) (string, bool) {
	f, ok := d.trustedManifestFor(vaultName, scope)
	if !ok {
		return "", false
	}
	text, ok := f.Describe[name]
	if !ok || text == "" {
		return "", false
	}
	return text, true
}

// manifestScopeDescription returns what a trusted .byn says about the project
// or directory itself.
func (d *Daemon) manifestScopeDescription(vaultName string, scope vault.Scope) (string, bool) {
	f, ok := d.trustedManifestFor(vaultName, scope)
	if !ok || f.Description == "" {
		return "", false
	}
	return f.Description, true
}

// manifestDescriptions returns every per-variable description a trusted .byn
// declares for scope, for a listing.
func (d *Daemon) manifestDescriptions(vaultName string, scope vault.Scope) map[string]string {
	f, ok := d.trustedManifestFor(vaultName, scope)
	if !ok {
		return nil
	}
	return f.Describe
}

// trustedManifestFor finds the most specific verified trust record governing
// scope and returns its snapshot, parsed.
//
// Specificity matches policyFor's: a record naming vault+project+env beats one
// naming vault+project, which beats a vault-only record. Ties keep the first,
// because two records at the same specificity for the same scope are a
// configuration the owner has to resolve, and picking one arbitrarily is no
// worse than picking the other — neither is granted anything by being chosen.
func (d *Daemon) trustedManifestFor(vaultName string, scope vault.Scope) (bynfile.File, bool) {
	store, err := trust.Load(d.cfg.Dir)
	if err != nil || len(store.Records) == 0 {
		return bynfile.File{}, false
	}

	// The vault key proves more than the machine fingerprint does, so use it
	// when the vault is open and fall back when it is not.
	var vkKey []byte
	if e := d.lookupVault(vaultName); e != nil && !e.store.IsLocked() {
		if k, kerr := e.store.DeriveSubkey(trust.VKMACKeyInfo); kerr == nil {
			vkKey = k
			defer zeroBytes(vkKey)
		}
	}

	reqProject := defaultIfEmpty(scope.Project, vault.DefaultProjectName)
	reqEnv := defaultIfEmpty(scope.Env, vault.DefaultEnvName)

	best := -1
	var bestRec trust.Record
	for _, rec := range store.Records {
		if !rec.IsV2() || rec.Snapshot == "" {
			continue
		}
		if defaultIfEmpty(rec.Vault, vault.DefaultVaultName) != vaultName {
			continue
		}
		if vkKey != nil {
			if !rec.VerifyVKMAC(vkKey) {
				continue
			}
		} else if !rec.VerifyFPMAC(d.fpMACKey) {
			continue
		}

		var spec int
		switch {
		case rec.ScopeProject == "" && rec.ScopeEnv == "":
			spec = 1
		case rec.ScopeEnv == "":
			if defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName) != reqProject {
				continue
			}
			spec = 2
		default:
			if defaultIfEmpty(rec.ScopeProject, vault.DefaultProjectName) != reqProject ||
				defaultIfEmpty(rec.ScopeEnv, vault.DefaultEnvName) != reqEnv {
				continue
			}
			spec = 3
		}
		if spec > best {
			best, bestRec = spec, rec
		}
	}
	if best < 0 {
		return bynfile.File{}, false
	}
	f, perr := bynfile.Parse([]byte(bestRec.Snapshot))
	if perr != nil {
		return bynfile.File{}, false
	}
	return f, true
}
