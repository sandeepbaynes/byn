package daemon

import (
	"github.com/sandeepbaynes/byn/internal/bynfile"
	"github.com/sandeepbaynes/byn/internal/trust"
)

// policyOf projects a parsed .byn onto the authority it requests, discarding
// everything about how the file is written.
func policyOf(f bynfile.File) trust.Policy {
	return trust.Policy{
		Vault:     f.Scope.Vault,
		Project:   f.Scope.Project,
		Env:       f.Scope.Env,
		EnvGrants: []string(f.Exec.Env),
		Actions:   []string(f.Exec.Actions),
		Writable:  f.Exec.Writable,
		Aliases:   f.Aliases,
		Auth:      f.Auth,
	}
}

// reconcileChanged decides whether a .byn whose bytes no longer match its trust
// record is actually asking for anything new.
//
// Trust used to be pinned to content hash and mtime, so a reordered list, an
// added comment, or a `git checkout` that only rewrote mtimes blocked every
// command in the project until a human retyped the master password. What
// actually needs consent is a request for MORE authority, so that is what gets
// compared.
//
// The granted policy is read back from the record's snapshot, which is already
// covered by the record MAC — so it is as trustworthy as the actions and auth
// tables alongside it, and no new record fields or MAC version are needed.
//
// Returns ok=true when the change is within the granted authority. The returned
// policy is the CURRENT file's, and callers must enforce with it rather than the
// record's copy: a file that dropped an action has narrowed, and continuing to
// honour the recorded wider set would ignore what the author just asked for.
func reconcileChanged(rec trust.Record, currentBody []byte) (effective trust.Policy, delta trust.Delta, ok bool) {
	if rec.Snapshot == "" {
		return trust.Policy{}, trust.Delta{}, false // pre-snapshot record: nothing to compare against
	}
	grantedFile, gerr := bynfile.Parse([]byte(rec.Snapshot))
	if gerr != nil {
		return trust.Policy{}, trust.Delta{}, false
	}
	currentFile, cerr := bynfile.Parse(currentBody)
	if cerr != nil {
		return trust.Policy{}, trust.Delta{}, false // unparseable: fail closed
	}
	current := policyOf(currentFile)
	delta = trust.ComparePolicies(policyOf(grantedFile), current)
	if delta.NeedsApproval() {
		return current, delta, false
	}
	return current, delta, true
}

// applyPolicy overlays the effective policy onto a trust record, so enforcement
// follows the file as it stands now. Only ever called with a policy that
// reconcileChanged found to be no wider than the grant, which makes every
// difference a restriction.
func applyPolicy(rec trust.Record, p trust.Policy) trust.Record {
	rec.Actions = p.Actions
	rec.Auth = p.Auth
	rec.Aliases = p.Aliases
	rec.EnvGrants = p.EnvGrants
	return rec
}
