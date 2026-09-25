package daemon

import (
	"context"
	"sort"

	"github.com/sandeepbaynes/byn/internal/ipc"
	"github.com/sandeepbaynes/byn/internal/vault"
)

// Values stored unattended, and bringing them under the master password.
//
// A value an agent stores while the vault is locked is sealed under the scope's
// authored key, which this machine holds in its trust records — so it is
// protected by the machine, not by the password (see vault/authored.go). That
// is the right trade at the moment of writing and the wrong one to leave in
// place: nothing ever asked the owner to adopt such a value, so it stayed on
// the weaker footing indefinitely, and a grant for another env could not open
// it at all. The list makes them visible; the import is the owner saying
// "this one is mine now".

// handleUnattendedList names every value in a vault still stored unattended.
// Names only, and it works locked: listing names never needed a credential.
func (d *Daemon) handleUnattendedList(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.UnattendedListReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	st, errEnv := d.storeForVault(env.ID, req.Scope.Vault)
	if errEnv != nil {
		return errEnv
	}
	items, err := st.ListUnattended(ctx)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	resp, err := ipc.NewResponse(env.ID, ipc.UnattendedListResp{Items: toUnattendedItems(items)})
	if err != nil {
		return internalErr(env.ID, err)
	}
	return resp
}

// handleUnattendedImport re-seals unattended values under the vault key.
//
// Authorized like an update — a session or fresh credentials — because it is
// the owner adopting a value someone else put there. It needs the vault key as
// well: an unlocked vault has it, a locked one is opened for the duration of
// the call with the password and not left unlocked.
func (d *Daemon) handleUnattendedImport(ctx context.Context, env *ipc.Envelope) *ipc.Envelope {
	var req ipc.UnattendedImportReq
	if err := ipc.DecodeBody(ipc.BodyReq, env, &req); err != nil {
		return badRequest(env.ID, err)
	}
	defer zero(req.Password)
	st, scope, errEnv := d.scopeFor(env.ID, req.Scope)
	if errEnv != nil {
		return errEnv
	}
	vaultName := defaultIfEmpty(req.Scope.Vault, vault.DefaultVaultName)

	all, err := st.ListUnattended(ctx)
	if err != nil {
		return mapVaultErr(env.ID, err)
	}
	targets, skipped := selectUnattended(all, scope, req.Names, req.All)

	if req.DryRun || len(targets) == 0 {
		return importResponse(env.ID, targets, skipped)
	}

	if le := d.authorizeAction(ctx, env.ID, vaultName, scope, st, "update", req.Password, req.PresenceToken); le != nil {
		d.auditPlane(ctx, req.Scope, "env_var", "*", "import.unattended", le)
		return le
	}
	var vk []byte
	if st.IsLocked() {
		if len(req.Password) == 0 {
			return ipc.NewError(env.ID, ipc.CodeLocked,
				"importing re-encrypts these values with the vault key, and the vault is locked",
				"byn unlock, or pass --password-stdin")
		}
		k, uerr := st.UnwrapVaultKey(req.Password)
		if uerr != nil {
			return mapVaultErr(env.ID, uerr)
		}
		defer zero(k)
		vk = k
	}

	var imported []vault.UnattendedEntry
	touched := make(map[vault.Scope]struct{})
	for _, t := range targets {
		sc := vault.Scope{Project: t.Project, Env: t.Env}
		var ok bool
		var serr error
		if vk != nil {
			ok, serr = st.SealUnattendedWithKey(ctx, vk, sc, t.Name)
		} else {
			ok, serr = st.SealUnattended(ctx, sc, t.Name)
		}
		ipcScope := ipc.Scope{Vault: vaultName, Project: t.Project, Env: t.Env}
		if serr != nil {
			le := mapVaultErr(env.ID, serr)
			d.auditPlane(ctx, ipcScope, "env_var", t.Name, "import.unattended", le)
			return le
		}
		if !ok {
			// Replaced by an ordinary write between the listing and now: it is
			// already protected, which is what was asked for.
			skipped = append(skipped, ipc.UnattendedSkip{Name: t.Name, Reason: "already protected by the master password"})
			continue
		}
		imported = append(imported, t)
		touched[sc] = struct{}{}
		// The value is the owner's now. The agent that stored it loses the
		// right to read or replace it as its own, exactly as when a person
		// overwrites it.
		if d.authored != nil {
			k := authoredScopeKey(vaultName, sc, "")
			_ = d.authored.Forget(k.Vault, k.Project, k.Env, t.Name)
		}
		d.auditPlane(ctx, ipcScope, "env_var", t.Name, "import.unattended", nil)
	}
	d.touchVault(req.Scope.Vault)
	// A re-sealed row no longer opens with the authored key a grant carried
	// for it, so every grant that may inject it is re-sealed with the key
	// that does — including, for a default-env value, the grants of every env
	// that inherits it.
	for sc := range touched {
		d.refreshCapabilitiesWithKey(ctx, st, vk, vaultName, sc)
	}
	return importResponse(env.ID, imported, skipped)
}

// selectUnattended narrows the vault's unattended values to what was asked for.
func selectUnattended(all []vault.UnattendedEntry, scope vault.Scope, names []string, everything bool) ([]vault.UnattendedEntry, []ipc.UnattendedSkip) {
	if everything {
		return all, nil
	}
	project := defaultIfEmpty(scope.Project, vault.DefaultProjectName)
	envName := defaultIfEmpty(scope.Env, vault.DefaultEnvName)
	inScope := make(map[string]vault.UnattendedEntry)
	for _, u := range all {
		if u.Project == project && u.Env == envName {
			inScope[u.Name] = u
		}
	}
	if len(names) == 0 {
		out := make([]vault.UnattendedEntry, 0, len(inScope))
		for _, u := range inScope {
			out = append(out, u)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	var out []vault.UnattendedEntry
	var skipped []ipc.UnattendedSkip
	for _, n := range names {
		if u, ok := inScope[n]; ok {
			out = append(out, u)
			continue
		}
		reason := "not an unattended value in " + project + "/" + envName
		for _, u := range all {
			if u.Project == project && u.Name == n && u.Env == vault.DefaultEnvName {
				reason = "inherited from default — import it there: --env default"
				break
			}
		}
		skipped = append(skipped, ipc.UnattendedSkip{Name: n, Reason: reason})
	}
	return out, skipped
}

func importResponse(id string, imported []vault.UnattendedEntry, skipped []ipc.UnattendedSkip) *ipc.Envelope {
	resp, err := ipc.NewResponse(id, ipc.UnattendedImportResp{
		Imported: toUnattendedItems(imported),
		Skipped:  skipped,
	})
	if err != nil {
		return internalErr(id, err)
	}
	return resp
}

func toUnattendedItems(in []vault.UnattendedEntry) []ipc.UnattendedItem {
	out := make([]ipc.UnattendedItem, 0, len(in))
	for _, u := range in {
		out = append(out, ipc.UnattendedItem{Project: u.Project, Env: u.Env, Name: u.Name})
	}
	return out
}
